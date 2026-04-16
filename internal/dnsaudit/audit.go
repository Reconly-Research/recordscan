package dnsaudit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"

	"recordscan/internal/model"
)

// Run performs DNS collection and maps checks to model.Findings.
func Run(ctx context.Context, apex string, timeout time.Duration, httpClient *http.Client) model.DNSReport {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	zoneFQDN := dns.Fqdn(strings.Trim(strings.TrimSpace(apex), "."))
	zone := strings.TrimSuffix(zoneFQDN, ".")
	report := model.DNSReport{
		Zone:            zone,
		RawRecords:      map[string][]string{},
		TechnicalDetail: map[string]any{},
	}

	c := &dns.Client{Net: "udp", Timeout: timeout}

	m := new(dns.Msg)
	m.SetQuestion(zoneFQDN, dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.ExchangeContext(ctx, m, publicResolver())
	if err != nil {
		report.Findings = append(report.Findings, model.Finding{
			ID:             "dns-resolution-failure",
			Category:       "dns_resolution",
			Severity:       "high",
			Title:          "DNS resolution failure for apex",
			Detail:         err.Error(),
			Recommendation: "Verify delegation, glue records, and resolvers allow UDP/TCP 53.",
		})
		return report
	}

	collectFromMsg(report.RawRecords, r)

	nsHosts := report.RawRecords["NS"]
	if len(nsHosts) == 0 {
		nsHosts = lookupSlice(ctx, c, zoneFQDN, dns.TypeNS)
		report.RawRecords["NS"] = nsHosts
	}
	report.Nameservers = append([]string(nil), nsHosts...)

	for _, pair := range []struct {
		typ uint16
	}{
		{dns.TypeAAAA},
		{dns.TypeMX},
		{dns.TypeTXT},
		{dns.TypeCAA},
		{dns.TypeSOA},
		{dns.TypeCNAME},
	} {
		key := typeKey(pair.typ)
		if len(report.RawRecords[key]) > 0 {
			continue
		}
		report.RawRecords[key] = lookupSlice(ctx, c, zoneFQDN, pair.typ)
	}

	dmarc := lookupSlice(ctx, c, "_dmarc."+zoneFQDN, dns.TypeTXT)
	if len(dmarc) > 0 {
		report.RawRecords["DMARC"] = dmarc
	}
	dkim := lookupSlice(ctx, c, "default._domainkey."+zoneFQDN, dns.TypeTXT)
	if len(dkim) > 0 {
		report.RawRecords["DKIM_default"] = dkim
	}

	if ds, err := dohResolve(ctx, httpClient, zone, dns.TypeDS); err == nil {
		report.TechnicalDetail["doh_ds"] = ds
	}
	if dk, err := dohResolve(ctx, httpClient, zone, dns.TypeDNSKEY); err == nil {
		report.TechnicalDetail["doh_dnskey"] = dk
	}

	report.Findings = append(report.Findings, auditEmail(zone, report.RawRecords)...)

	if len(report.RawRecords["MX"]) == 0 {
		report.Findings = append(report.Findings, model.Finding{
			ID:             "dns-missing-mx",
			Category:       "email",
			Severity:       "medium",
			Title:          "No MX records",
			Detail:         "The zone has no MX records. Mail may use A/AAAA fallback or external routing only.",
			Recommendation: "Publish MX records for your inbound mail gateways if this domain receives email.",
		})
	}

	report.Findings = append(report.Findings, auditCAA(report.RawRecords["CAA"])...)
	report.Findings = append(report.Findings, auditPrivateIP(report.RawRecords)...)
	report.Findings = append(report.Findings, detectWildcard(ctx, c, zoneFQDN)...)

	if ttl := firstTTL(r); ttl > 0 {
		report.TechnicalDetail["sample_ttl_seconds"] = ttl
		report.Findings = append(report.Findings, auditTTL(ttl)...)
	}

	report.Findings = append(report.Findings, auditNSRedundancy(nsHosts)...)
	report.Findings = append(report.Findings, compareNSAnswers(ctx, c, zoneFQDN, nsHosts)...)
	report.Findings = append(report.Findings, tryAXFR(zoneFQDN, nsHosts, timeout)...)
	report.Findings = append(report.Findings, auditDanglingNS(ctx, c, nsHosts)...)
	report.Findings = append(report.Findings, auditNSCNAME(ctx, c, nsHosts)...)
	report.Findings = append(report.Findings, auditUncommonRecords(ctx, c, zoneFQDN)...)
	report.Findings = append(report.Findings, auditTXT(report.RawRecords["TXT"])...)
	report.Findings = append(report.Findings, auditThirdPartyTXT(report.RawRecords["TXT"])...)

	targets := append([]string{}, report.RawRecords["A"]...)
	targets = append(targets, report.RawRecords["AAAA"]...)
	targets = append(targets, flattenCNAMEChain(ctx, c, zoneFQDN, report.RawRecords["CNAME"])...)
	report.Findings = append(report.Findings, auditInfrastructureFingerprints(targets, report.RawRecords)...)

	report.Findings = append(report.Findings, auditDNSSEC(ctx, httpClient, zone)...)

	if len(report.RawRecords["AAAA"]) == 0 && len(report.RawRecords["A"]) > 0 {
		report.Findings = append(report.Findings, model.Finding{
			ID:             "dns-ipv6-missing",
			Category:       "dns_configuration",
			Severity:       "low",
			Title:          "No AAAA while A exists",
			Detail:         "IPv6-only clients may not reach this name natively.",
			Recommendation: "Publish AAAA if your edge supports IPv6.",
		})
	}

	report.Findings = append(report.Findings, auditApexLabels(zone)...)

	sortFindings(report.Findings)
	return report
}

func publicResolver() string {
	return "8.8.8.8:53"
}

func typeKey(t uint16) string {
	switch t {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeNS:
		return "NS"
	case dns.TypeMX:
		return "MX"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeCAA:
		return "CAA"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypeCNAME:
		return "CNAME"
	default:
		return "OTHER"
	}
}

func lookupSlice(ctx context.Context, c *dns.Client, name string, qtype uint16) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)
	r, _, err := c.ExchangeContext(ctx, m, publicResolver())
	if err != nil || r == nil {
		return nil
	}
	tmp := map[string][]string{}
	collectFromMsg(tmp, r)
	return tmp[typeKey(qtype)]
}

func collectFromMsg(dst map[string][]string, r *dns.Msg) {
	if r == nil {
		return
	}
	for _, a := range append(append([]dns.RR{}, r.Answer...), r.Ns...) {
		switch rr := a.(type) {
		case *dns.A:
			dst["A"] = appendUnique(dst["A"], rr.A.String())
		case *dns.AAAA:
			dst["AAAA"] = appendUnique(dst["AAAA"], rr.AAAA.String())
		case *dns.NS:
			dst["NS"] = appendUnique(dst["NS"], strings.TrimSuffix(rr.Ns, "."))
		case *dns.MX:
			line := fmt.Sprintf("%d %s", rr.Preference, strings.TrimSuffix(rr.Mx, "."))
			dst["MX"] = appendUnique(dst["MX"], line)
		case *dns.TXT:
			dst["TXT"] = appendUnique(dst["TXT"], strings.Join(rr.Txt, ""))
		case *dns.CNAME:
			dst["CNAME"] = appendUnique(dst["CNAME"], strings.TrimSuffix(rr.Target, "."))
		case *dns.SOA:
			dst["SOA"] = appendUnique(dst["SOA"], strings.TrimSuffix(rr.Ns, ".")+" "+strings.TrimSuffix(rr.Mbox, "."))
		case *dns.CAA:
			dst["CAA"] = appendUnique(dst["CAA"], fmt.Sprintf("%d %s \"%s\"", rr.Flag, rr.Tag, rr.Value))
		}
	}
}

func appendUnique(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func firstTTL(r *dns.Msg) int {
	if r == nil {
		return 0
	}
	for _, a := range r.Answer {
		if a.Header().Ttl > 0 {
			return int(a.Header().Ttl)
		}
	}
	return 0
}

func auditEmail(zone string, raw map[string][]string) []model.Finding {
	var out []model.Finding
	var spf string
	for _, t := range raw["TXT"] {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = t
			break
		}
	}
	if spf == "" {
		out = append(out, model.Finding{
			ID:             "dns-missing-spf",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "Missing SPF record",
			Detail:         "No apex TXT record starting with v=spf1.",
			Recommendation: "Publish SPF that authorizes legitimate senders and ends with -all or ~all.",
		})
	} else {
		low := strings.ToLower(spf)
		if strings.Contains(low, "+all") {
			out = append(out, model.Finding{
				ID:             "dns-spf-permissive",
				Category:       "email_auth",
				Severity:       "critical",
				Title:          "SPF allows any sender (+all)",
				Detail:         spf,
				Recommendation: "Remove +all; enumerate real sending sources.",
			})
		}
		if strings.HasSuffix(strings.TrimSpace(low), "?all") {
			out = append(out, model.Finding{
				ID:             "dns-spf-neutral",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "SPF ends with ?all (neutral)",
				Detail:         spf,
				Recommendation: "Use -all or ~all for a clear policy.",
			})
		}
		if !strings.Contains(low, "-all") && !strings.Contains(low, "~all") {
			out = append(out, model.Finding{
				ID:             "dns-spf-no-fail",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "SPF lacks -all/~all terminator",
				Detail:         spf,
				Recommendation: "End SPF with -all or ~all.",
			})
		}
	}

	if len(raw["DMARC"]) == 0 {
		out = append(out, model.Finding{
			ID:             "dns-missing-dmarc",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "Missing DMARC record",
			Detail:         fmt.Sprintf("No TXT at _dmarc.%s.", zone),
			Recommendation: "Publish v=DMARC1 with p= and rua/ruf.",
		})
	} else {
		d := strings.ToLower(strings.Join(raw["DMARC"], " "))
		if !strings.Contains(d, "v=dmarc1") {
			out = append(out, model.Finding{
				ID:             "dns-dmarc-malformed",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "DMARC record may be malformed",
				Detail:         strings.Join(raw["DMARC"], " | "),
				Recommendation: "Start DMARC with v=DMARC1.",
			})
		}
		if strings.Contains(d, "p=none") {
			out = append(out, model.Finding{
				ID:             "dns-dmarc-monitor-only",
				Category:       "email_auth",
				Severity:       "low",
				Title:          "DMARC policy is p=none",
				Detail:         strings.Join(raw["DMARC"], " | "),
				Recommendation: "Tighten to quarantine/reject after monitoring.",
			})
		}
		if !strings.Contains(d, "p=") {
			out = append(out, model.Finding{
				ID:             "dns-dmarc-no-policy",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "DMARC missing p= tag",
				Detail:         strings.Join(raw["DMARC"], " | "),
				Recommendation: "Set explicit p=none|quarantine|reject.",
			})
		}
	}

	if len(raw["DKIM_default"]) == 0 {
		out = append(out, model.Finding{
			ID:             "dns-missing-dkim-sample",
			Category:       "email_auth",
			Severity:       "info",
			Title:          "No default._domainkey TXT (sample selector)",
			Detail:         "Only default selector checked; verify active selectors separately.",
			Recommendation: "Publish DKIM for each active mail signing selector.",
		})
	} else {
		out = append(out, auditDKIMStrength(raw["DKIM_default"])...)
	}
	return out
}

func auditDKIMStrength(records []string) []model.Finding {
	var out []model.Finding
	re := regexp.MustCompile(`p=([A-Za-z0-9+/=]+)`)
	for _, r := range records {
		if !strings.Contains(strings.ToLower(r), "k=rsa") {
			continue
		}
		m := re.FindStringSubmatch(r)
		if len(m) != 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			out = append(out, model.Finding{
				ID:             "dns-dkim-key-decode",
				Category:       "email_auth",
				Severity:       "low",
				Title:          "DKIM public key may be malformed",
				Detail:         err.Error(),
				Recommendation: "Validate DKIM TXT encoding and p= payload.",
			})
			continue
		}
		bits := len(raw) * 8
		if bits > 0 && bits < 2048 {
			out = append(out, model.Finding{
				ID:             "dns-dkim-key-weak",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "DKIM RSA modulus appears under 2048-bit",
				Detail:         fmt.Sprintf("Decoded modulus ~%d bits", bits),
				Recommendation: "Rotate to >=2048-bit RSA or ed25519.",
			})
		}
	}
	return out
}

func auditCAA(records []string) []model.Finding {
	if len(records) == 0 {
		return []model.Finding{{
			ID:             "dns-missing-caa",
			Category:       "dns_vulnerabilities",
			Severity:       "medium",
			Title:          "No CAA records",
			Detail:         "Any public CA could issue certificates for this domain unless constrained elsewhere.",
			Recommendation: "Publish CAA limiting issuance to CAs you use; set issuewild if applicable.",
		}}
	}
	var out []model.Finding
	var hasIssue bool
	for _, r := range records {
		low := strings.ToLower(r)
		if strings.Contains(low, "issue \"") || strings.Contains(low, "issuewild \"") {
			hasIssue = true
		}
		if strings.Contains(low, "issue \";\"") || strings.Contains(low, "issuewild \";\"") {
			out = append(out, model.Finding{
				ID:             "dns-caa-empty-issue",
				Category:       "dns_configuration",
				Severity:       "info",
				Title:          "CAA contains empty issue/issuewild",
				Detail:         r,
				Recommendation: "Confirm this intentionally forbids issuance via empty tag semantics.",
			})
		}
	}
	if !hasIssue {
		out = append(out, model.Finding{
			ID:             "dns-caa-no-issue",
			Category:       "dns_configuration",
			Severity:       "low",
			Title:          "CAA present but no issue/issuewild observed",
			Detail:         strings.Join(records, " | "),
			Recommendation: "Add issue tags for authorized CAs.",
		})
	}
	return out
}

func auditPrivateIP(raw map[string][]string) []model.Finding {
	var out []model.Finding
	for _, ip := range raw["A"] {
		if p := net.ParseIP(ip); p != nil && p.IsPrivate() {
			out = append(out, model.Finding{
				ID:             "dns-private-ip-a",
				Category:       "attack_surface",
				Severity:       "high",
				Title:          "A record resolves to private address",
				Detail:         ip,
				Recommendation: "Avoid publishing RFC1918 addresses publicly; risk of DNS rebinding and split-horizon leaks.",
				Evidence:       []string{ip},
			})
		}
	}
	for _, ip := range raw["AAAA"] {
		if p := net.ParseIP(ip); p != nil && (p.IsPrivate() || p.IsLoopback()) {
			out = append(out, model.Finding{
				ID:             "dns-private-ip-aaaa",
				Category:       "attack_surface",
				Severity:       "high",
				Title:          "AAAA record resolves to non-public address",
				Detail:         ip,
				Recommendation: "Publish only public IPv6 for internet-facing names.",
				Evidence:       []string{ip},
			})
		}
	}
	return out
}

func detectWildcard(ctx context.Context, c *dns.Client, zoneFQDN string) []model.Finding {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	label := "rw-" + hex.EncodeToString(b)
	name := dns.Fqdn(label + "." + strings.TrimSuffix(zoneFQDN, "."))
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.RecursionDesired = true
	r, _, err := c.ExchangeContext(ctx, m, publicResolver())
	if err != nil || r == nil || len(r.Answer) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:             "dns-wildcard-detected",
		Category:       "advanced_dns",
		Severity:       "info",
		Title:          "Wildcard DNS suspected",
		Detail:         fmt.Sprintf("Random label %s returned answers.", strings.TrimSuffix(name, ".")),
		Recommendation: "Review whether catch-all DNS is intended; it expands phishing and takeover surface.",
	}}
}
