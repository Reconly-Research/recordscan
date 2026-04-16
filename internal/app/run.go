package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"recordscan/internal/dnsaudit"
	"recordscan/internal/httpaudit"
	"recordscan/internal/logging"
	"recordscan/internal/model"
	"recordscan/internal/output"
	"recordscan/internal/report"
	"recordscan/internal/sslaudit"
	"recordscan/internal/ui"
	"recordscan/internal/util"
)

type Config struct {
	Target     string
	OutRoot    string
	Timeout    time.Duration
	LogoutPath string
	SkipDNS    bool
	SkipSSL    bool
	SkipHTTP   bool
	SSLPort    int
}

// Run executes audits and writes scan.json + PDF. progress and logger may be nil.
func Run(cfg Config, logger *logging.Logger, progress *ui.Progress) (model.ScanReport, output.Paths, error) {
	var empty output.Paths
	start := time.Now()
	host, tlsPort, baseURL := util.ParseTarget(cfg.Target)
	if host == "" {
		return model.ScanReport{}, empty, fmt.Errorf("empty target")
	}
	if cfg.SSLPort > 0 {
		tlsPort = cfg.SSLPort
	}

	safeName := util.SanitizeFilename(host)
	baseDir := filepath.Join(cfg.OutRoot, safeName)
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return model.ScanReport{}, empty, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*3)
	defer cancel()

	httpClient := &http.Client{Timeout: cfg.Timeout}

	if logger == nil {
		logger = logging.New(false, true)
	}

	rep := model.ScanReport{
		Metadata: model.ScanMetadata{
			ToolVersion:  model.Version,
			TargetHost:   host,
			ScannedAtUTC: time.Now().UTC().Format(time.RFC3339),
			Elapsed:      time.Since(start).String(),
			OutDir:       baseDir,
		},
		DNS:  model.DNSReport{Zone: host, Findings: nil},
		SSL:  model.SSLReport{Host: host, Port: tlsPort, Findings: nil},
		HTTP: model.HTTPReport{BaseURL: baseURL, Findings: nil},
	}

	logger.Info("scan started", fmt.Sprintf("target=%s out=%s", host, baseDir))

	if !cfg.SkipDNS {
		if progress != nil {
			progress.Update("DNS audit", "Resolving A/AAAA/NS/MX/TXT/CAA, DMARC/DKIM, zone checks")
		}
		logger.Info("gathering DNS", "apex records, email auth, NS consistency, AXFR probe, DNSSEC hints")
		rep.DNS = dnsaudit.Run(ctx, host, cfg.Timeout, httpClient)
		logger.Info("DNS complete", fmt.Sprintf("findings=%d nameservers=%d", len(rep.DNS.Findings), len(rep.DNS.Nameservers)))
	} else {
		logger.Info("skipping DNS audit", "-skip-dns")
	}

	if !cfg.SkipSSL {
		if progress != nil {
			progress.Update("TLS audit", fmt.Sprintf("Handshake and ciphers on %s:%d", host, tlsPort))
		}
		logger.Info("gathering TLS", fmt.Sprintf("host=%s port=%d protocols ciphers certificate", host, tlsPort))
		rep.SSL = sslaudit.Run(ctx, host, tlsPort, cfg.Timeout)
		if rep.SSL.Grading != nil {
			logger.Info("TLS complete", fmt.Sprintf("grade=%s score=%d", rep.SSL.Grading.OverallGrade, rep.SSL.Grading.OverallScore))
		} else if rep.SSL.Error != "" {
			logger.Info("TLS incomplete", rep.SSL.Error)
		} else {
			logger.Info("TLS complete", fmt.Sprintf("findings=%d", len(rep.SSL.Findings)))
		}
	} else {
		logger.Info("skipping TLS audit", "-skip-ssl")
	}

	if !cfg.SkipHTTP && baseURL != "" {
		if progress != nil {
			progress.Update("HTTP headers", sanitizeMeta(baseURL))
		}
		logger.Info("gathering HTTP security headers", sanitizeMeta(baseURL))
		rep.HTTP = httpaudit.Run(ctx, baseURL, cfg.LogoutPath, cfg.Timeout)
		logger.Info("HTTP complete", fmt.Sprintf("status=%d tests_pass=%d tests_fail=%d", rep.HTTP.StatusCode, countHTTPPassed(rep.HTTP.Tests), countHTTPFailed(rep.HTTP.Tests)))
	} else if cfg.SkipHTTP {
		logger.Info("skipping HTTP audit", "-skip-http")
	} else {
		logger.Info("skipping HTTP audit", "no base URL")
	}

	rep.Metadata.Elapsed = time.Since(start).String()
	rep.Summary = summarize(rep)

	if progress != nil {
		progress.Update("Writing outputs", "scan.json and recordscan-report.pdf")
	}
	logger.Info("writing scan.json", baseDir)
	paths, err := output.WriteJSON(baseDir, rep)
	if err != nil {
		return rep, paths, err
	}
	logger.Info("writing PDF report", baseDir)
	pdfPath, err := report.WritePDF(baseDir, rep)
	if err != nil {
		return rep, paths, err
	}
	paths.PDF = pdfPath

	logger.Info("scan finished", fmt.Sprintf("elapsed=%s findings=%d", rep.Metadata.Elapsed, rep.Summary.FindingsTotal))
	return rep, paths, nil
}

func sanitizeMeta(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func countHTTPPassed(tests []model.HTTPTest) int {
	n := 0
	for _, t := range tests {
		if !t.Skipped && t.Passed {
			n++
		}
	}
	return n
}

func countHTTPFailed(tests []model.HTTPTest) int {
	n := 0
	for _, t := range tests {
		if !t.Skipped && !t.Passed {
			n++
		}
	}
	return n
}

func summarize(rep model.ScanReport) model.ScanSummary {
	s := model.ScanSummary{
		BySeverity: map[string]int{},
	}

	add := func(ff []model.Finding) {
		for _, f := range ff {
			k := strings.ToLower(f.Severity)
			if k == "" {
				k = "unknown"
			}
			s.BySeverity[k]++
			s.FindingsTotal++
		}
	}

	add(rep.DNS.Findings)
	add(rep.SSL.Findings)
	add(rep.HTTP.Findings)

	s.DNSFindingCount = len(rep.DNS.Findings)
	s.SSLFindingCount = len(rep.SSL.Findings)
	s.HTTPFindingCount = len(rep.HTTP.Findings)

	for _, t := range rep.HTTP.Tests {
		if t.Skipped {
			s.HTTPTestsSkipped++
			continue
		}
		if t.Passed {
			s.HTTPTestsPassed++
		} else {
			s.HTTPTestsFailed++
		}
	}

	if rep.SSL.Grading != nil {
		s.SSLGrade = rep.SSL.Grading.OverallGrade
		s.SSLProtocolScore = rep.SSL.Grading.ProtocolScore
		s.SSLCertificateScore = rep.SSL.Grading.CertificateScore
	}

	return s
}
