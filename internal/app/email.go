package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"recordscan/internal/emailsec"
	"recordscan/internal/logging"
	"recordscan/internal/model"
	"recordscan/internal/output"
	"recordscan/internal/report"
	"recordscan/internal/ui"
	"recordscan/internal/util"
)

// EmailConfig configures the dedicated email security assessment.
type EmailConfig struct {
	Target  string
	OutRoot string
	Timeout time.Duration
}

// RunEmail executes email authentication / transport checks and writes JSON + PDF.
func RunEmail(cfg EmailConfig, logger *logging.Logger, progress *ui.Progress) (model.EmailSecReport, output.Paths, error) {
	var empty output.Paths
	host, _, _ := util.ParseTarget(cfg.Target)
	if host == "" {
		return model.EmailSecReport{}, empty, fmt.Errorf("empty domain")
	}

	start := time.Now()
	safeName := util.SanitizeFilename(host)
	baseDir := filepath.Join(cfg.OutRoot, safeName)
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return model.EmailSecReport{}, empty, err
	}

	if logger == nil {
		logger = logging.New(false, true)
	}

	httpClient := &http.Client{Timeout: cfg.Timeout}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*4)
	defer cancel()

	if progress != nil {
		progress.Update("Email security", "MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI")
	}
	logger.Info("email assessment started", fmt.Sprintf("zone=%s out=%s", host, baseDir))

	rep := emailsec.Run(ctx, host, cfg.Timeout, httpClient)
	rep.Metadata.OutDir = baseDir
	rep.Metadata.Elapsed = time.Since(start).String()

	logger.Info("email assessment complete", fmt.Sprintf("findings=%d posture=%s", rep.Summary.FindingsTotal, rep.Summary.PostureLabel))

	if progress != nil {
		progress.Update("Writing outputs", "email-sec-scan.json and recordscan-email-report.pdf")
	}
	paths, err := output.WriteEmailSecJSON(baseDir, rep)
	if err != nil {
		return rep, paths, err
	}
	pdfPath, err := report.WriteEmailPDF(baseDir, rep)
	if err != nil {
		return rep, paths, err
	}
	paths.PDF = pdfPath
	return rep, paths, nil
}
