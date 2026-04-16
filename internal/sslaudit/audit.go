package sslaudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"recordscan/internal/model"
)

// Run connects to host:port, evaluates certificate and protocol/cipher posture.
func Run(ctx context.Context, host string, port int, timeout time.Duration) model.SSLReport {
	if port <= 0 {
		port = 443
	}
	host = strings.Trim(strings.ToLower(host), ".")
	rep := model.SSLReport{Host: host, Port: port, Findings: nil}

	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	tlsCfgVerify := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfgVerify)
	verifiedOK := err == nil
	if err != nil {
		rep.Findings = append(rep.Findings, model.Finding{
			ID:             "ssl-verification-failed",
			Category:       "ssl",
			Severity:       "medium",
			Title:          "TLS chain verification failed (retrying with InsecureSkipVerify)",
			Detail:         err.Error(),
			Recommendation: "Serve a publicly trusted certificate that matches the hostname.",
		})
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		})
		if err != nil {
			rep.Error = err.Error()
			rep.Findings = append(rep.Findings, model.Finding{
				ID:             "ssl-handshake-failed",
				Category:       "ssl",
				Severity:       "high",
				Title:          "TLS handshake failed",
				Detail:         err.Error(),
				Recommendation: "Ensure TLS is enabled on this port and firewalls allow the connection.",
			})
			return rep
		}
	}
	rep.Connected = true
	st := conn.ConnectionState()
	rep.NegotiatedVersion = tlsVersionName(st.Version)
	rep.NegotiatedCipher = tls.CipherSuiteName(st.CipherSuite)
	_ = conn.Close()

	rep.Certificate = summarizeCert(host, st.PeerCertificates, verifiedOK)

	weakProtos := probeProtocols(ctx, dialer, addr, host, timeout)
	rep.SupportedProtocols = weakProtos.supported
	rep.WeakProtocolsEnabled = weakProtos.weak

	ciphers := probeCiphers(ctx, dialer, addr, host, timeout)
	rep.SupportedCiphers = ciphers

	rep.Grading = gradeSSL(rep, weakProtos, ciphers)
	rep.Findings = append(rep.Findings, sslFindings(rep)...)

	sort.Slice(rep.Findings, func(i, j int) bool {
		return rep.Findings[i].ID < rep.Findings[j].ID
	})
	return rep
}

func summarizeCert(host string, chain []*x509.Certificate, verifiedOK bool) *model.CertificateSummary {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	now := time.Now()
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)

	sanMatch := false
	h := strings.ToLower(host)
	for _, n := range leaf.DNSNames {
		if strings.ToLower(n) == h || matchWildcard(n, h) {
			sanMatch = true
			break
		}
	}
	if !sanMatch && strings.ToLower(leaf.Subject.CommonName) == h {
		sanMatch = true
	}

	return &model.CertificateSummary{
		SubjectCN:          leaf.Subject.CommonName,
		DNSNames:           append([]string{}, leaf.DNSNames...),
		IssuerCN:           leaf.Issuer.CommonName,
		NotBeforeUTC:       leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfterUTC:        leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry:    days,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		VerifiedChain:      verifiedOK,
		HostnameMatch:      sanMatch,
	}
}

func matchWildcard(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[2:]
	return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
}

type protoResult struct {
	supported []string
	weak      []string
}

func probeProtocols(ctx context.Context, dialer *net.Dialer, addr, serverName string, timeout time.Duration) protoResult {
	out := protoResult{}
	vers := []struct {
		name     string
		min, max uint16
		weak     bool
	}{
		{"TLS1.0", tls.VersionTLS10, tls.VersionTLS10, true},
		{"TLS1.1", tls.VersionTLS11, tls.VersionTLS11, true},
		{"TLS1.2", tls.VersionTLS12, tls.VersionTLS12, false},
		{"TLS1.3", tls.VersionTLS13, tls.VersionTLS13, false},
	}
	for _, v := range vers {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		cfg := &tls.Config{
			ServerName:         serverName,
			MinVersion:         v.min,
			MaxVersion:         v.max,
			InsecureSkipVerify: true,
		}
		d := *dialer
		if d.Timeout <= 0 {
			d.Timeout = timeout
		}
		c, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
		if err != nil {
			continue
		}
		_ = c.Close()
		out.supported = append(out.supported, v.name)
		if v.weak {
			out.weak = append(out.weak, v.name)
		}
	}
	return out
}

func supportsTLS12(s *tls.CipherSuite) bool {
	for _, v := range s.SupportedVersions {
		if v == tls.VersionTLS12 {
			return true
		}
	}
	return false
}

func probeCiphers(ctx context.Context, dialer *net.Dialer, addr, serverName string, timeout time.Duration) []model.CipherProbe {
	var out []model.CipherProbe
	suites := append(append([]*tls.CipherSuite{}, tls.CipherSuites()...), tls.InsecureCipherSuites()...)
	seen := map[uint16]struct{}{}
	for _, suite := range suites {
		if suite == nil || !supportsTLS12(suite) {
			continue
		}
		if _, ok := seen[suite.ID]; ok {
			continue
		}
		select {
		case <-ctx.Done():
			return out
		default:
		}
		cfg := &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{suite.ID},
			InsecureSkipVerify: true,
		}
		d := *dialer
		if d.Timeout <= 0 {
			d.Timeout = timeout
		}
		c, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
		if err != nil {
			continue
		}
		st := c.ConnectionState()
		_ = c.Close()
		score := cipherScore(suite.Name)
		if suite.Insecure && score > 50 {
			score = 50
		}
		seen[suite.ID] = struct{}{}
		out = append(out, model.CipherProbe{
			Protocol: tlsVersionName(st.Version),
			Name:     suite.Name,
			ID:       suite.ID,
			Score:    score,
		})
	}
	return out
}

func cipherScore(name string) int {
	n := strings.ToUpper(name)
	switch {
	case strings.Contains(n, "NULL"), strings.Contains(n, "EXPORT"), strings.Contains(n, "RC4"),
		strings.Contains(n, "DES-CBC-") && !strings.Contains(n, "3DES"),
		strings.Contains(n, "CBC") && (strings.Contains(n, "SHA") && strings.Contains(n, "RSA") && !strings.Contains(n, "GCM")):
		return 40
	case strings.Contains(n, "3DES"), strings.Contains(n, "CBC-SHA"):
		return 70
	case strings.Contains(n, "GCM"), strings.Contains(n, "CHACHA"):
		return 100
	default:
		return 85
	}
}

func gradeSSL(rep model.SSLReport, pr protoResult, ciphers []model.CipherProbe) *model.SSLGrading {
	g := &model.SSLGrading{
		ProtocolScore:    100,
		CertificateScore: 100,
		CipherScore:      100,
	}
	notes := []string{}

	for _, w := range pr.weak {
		notes = append(notes, "weak protocol "+w)
		if strings.HasPrefix(w, "TLS1.0") {
			if g.ProtocolScore > 60 {
				g.ProtocolScore = 60
			}
		}
		if strings.HasPrefix(w, "TLS1.1") {
			if g.ProtocolScore > 75 {
				g.ProtocolScore = 75
			}
		}
	}

	minCipher := 100
	for _, c := range ciphers {
		if c.Score < minCipher {
			minCipher = c.Score
		}
	}
	if len(ciphers) > 0 {
		g.CipherScore = minCipher
	}

	if rep.Certificate != nil {
		if rep.Certificate.DaysUntilExpiry < 0 {
			g.CertificateScore = 0
			notes = append(notes, "certificate expired")
		} else if rep.Certificate.DaysUntilExpiry <= 30 {
			g.CertificateScore -= 20
			notes = append(notes, "expiry within 30 days")
		}
		algo := strings.ToUpper(rep.Certificate.SignatureAlgorithm)
		if strings.Contains(algo, "SHA1") || strings.Contains(algo, "MD5") {
			g.CertificateScore -= 30
			notes = append(notes, "weak signature algorithm")
		}
		if !rep.Certificate.HostnameMatch {
			g.CertificateScore -= 25
			notes = append(notes, "hostname mismatch")
		}
		if g.CertificateScore < 0 {
			g.CertificateScore = 0
		}
	}

	g.OverallScore = (g.ProtocolScore*4 + g.CertificateScore*4 + g.CipherScore*2) / 10
	g.OverallGrade = scoreToGrade(g.OverallScore)
	g.Notes = strings.Join(notes, "; ")
	return g
}

func scoreToGrade(s int) string {
	switch {
	case s >= 95:
		return "A+"
	case s >= 90:
		return "A"
	case s >= 80:
		return "B"
	case s >= 70:
		return "C"
	case s >= 60:
		return "D"
	default:
		return "F"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func sslFindings(rep model.SSLReport) []model.Finding {
	var f []model.Finding
	for _, w := range rep.WeakProtocolsEnabled {
		f = append(f, model.Finding{
			ID:             "ssl-weak-protocol-" + strings.ToLower(strings.ReplaceAll(w, ".", "")),
			Category:       "ssl_protocol",
			Severity:       "high",
			Title:          "Legacy TLS enabled: " + w,
			Detail:         "Server negotiates deprecated protocol versions.",
			Recommendation: "Disable TLS 1.0/1.1; prefer TLS 1.2+ and TLS 1.3.",
		})
	}
	if rep.Certificate != nil {
		if rep.Certificate.DaysUntilExpiry < 0 {
			f = append(f, model.Finding{
				ID:             "ssl-cert-expired",
				Category:       "ssl_certificate",
				Severity:       "critical",
				Title:          "Certificate expired",
				Detail:         rep.Certificate.NotAfterUTC,
				Recommendation: "Renew and deploy a valid certificate.",
			})
		} else if rep.Certificate.DaysUntilExpiry <= 30 {
			f = append(f, model.Finding{
				ID:             "ssl-cert-expiring",
				Category:       "ssl_certificate",
				Severity:       "medium",
				Title:          "Certificate expiring within 30 days",
				Detail:         fmt.Sprintf("%d days remaining", rep.Certificate.DaysUntilExpiry),
				Recommendation: "Renew before expiry to avoid outages.",
			})
		}
		if !rep.Certificate.HostnameMatch {
			f = append(f, model.Finding{
				ID:             "ssl-name-mismatch",
				Category:       "ssl_certificate",
				Severity:       "high",
				Title:          "Certificate does not match hostname",
				Detail:         fmt.Sprintf("SANs: %v", rep.Certificate.DNSNames),
				Recommendation: "Issue a certificate covering the scanned hostname.",
			})
		}
		algo := strings.ToUpper(rep.Certificate.SignatureAlgorithm)
		if strings.Contains(algo, "SHA1") || strings.Contains(algo, "MD5") {
			f = append(f, model.Finding{
				ID:             "ssl-weak-signature",
				Category:       "ssl_certificate",
				Severity:       "high",
				Title:          "Certificate uses weak signature algorithm",
				Detail:         rep.Certificate.SignatureAlgorithm,
				Recommendation: "Reissue with SHA-256 or better.",
			})
		}
	}
	if rep.Grading != nil && (strings.HasPrefix(rep.Grading.OverallGrade, "D") || rep.Grading.OverallGrade == "F") {
		f = append(f, model.Finding{
			ID:             "ssl-low-grade",
			Category:       "ssl_grading",
			Severity:       "medium",
			Title:          "Overall TLS grade is weak",
			Detail:         fmt.Sprintf("Grade %s (score %d)", rep.Grading.OverallGrade, rep.Grading.OverallScore),
			Recommendation: "Align configuration with SSLLabs-style best practices.",
		})
	}
	return f
}
