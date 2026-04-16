package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-pdf/fpdf"

	"recordscan/internal/model"
)

const (
	pageW  = 210.0
	margin = 12.0
	bodyW  = pageW - 2*margin // 186
)

// WritePDF renders recordscan-report.pdf next to scan.json.
func WritePDF(baseDir string, rep model.ScanReport) (string, error) {
	out := filepath.Join(baseDir, "recordscan-report.pdf")
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin)
	reportFontFamily = configureReportFont(pdf)
	pdf.AddPage()
	pdf.SetTitle("Recordscan Report", false)
	pdf.SetAuthor("recordscan", false)

	drawPDFHeader(pdf)
	drawAssessmentOverview(pdf, rep)

	sectionTitle(pdf, "Executive summary")
	rowTableWrapped(pdf, summaryHeaders(), summaryValues(rep))
	sev := severityRow(rep)
	if sev != "" {
		pdf.SetFont(reportFontFamily, "", 8)
		pdf.SetTextColor(71, 85, 105)
		pdf.MultiCell(0, 4, sanitizePDF("By severity: "+sev), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
	}
	pdf.Ln(2)

	sectionTitle(pdf, "DNS records (apex)")
	drawDNSRecordsTable(pdf, rep.DNS)
	pdf.Ln(2)

	sectionTitle(pdf, "DNS findings")
	drawFindingsTable(pdf, rep.DNS.Findings)
	pdf.Ln(2)

	// Wide TLS/SSL tables: start on a fresh page so wrapped rows are not split across pages.
	pdf.AddPage()
	sectionTitle(pdf, "TLS / SSL summary")
	rowTableWrapped(pdf, tlsSummaryHeaders(), tlsSummaryValues(rep.SSL))
	pdf.Ln(1)
	if rep.SSL.Certificate != nil {
		rowTableWrapped(pdf, certHeaders(), certValues(rep.SSL.Certificate))
		if san := strings.Join(rep.SSL.Certificate.DNSNames, ", "); san != "" {
			pdf.SetFont(reportFontFamily, "", 8)
			pdf.SetTextColor(17, 24, 39)
			pdf.MultiCell(0, 4, sanitizePDF("SANs: "+san), "", "L", false)
			pdf.SetTextColor(0, 0, 0)
		}
		pdf.Ln(2)
	}
	if len(rep.SSL.WeakProtocolsEnabled) > 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(185, 28, 28)
		pdf.MultiCell(0, 5, sanitizePDF("Weak protocols enabled: "+strings.Join(rep.SSL.WeakProtocolsEnabled, ", ")), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(1)
	}
	if len(rep.SSL.SupportedCiphers) > 0 {
		sectionTitle(pdf, "TLS 1.2 cipher suites accepted")
		drawCipherTable(pdf, rep.SSL.SupportedCiphers)
		pdf.Ln(2)
	}
	if rep.SSL.Error != "" {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(185, 28, 28)
		pdf.MultiCell(0, 5, sanitizePDF("TLS error: "+rep.SSL.Error), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(2)
	}
	sectionTitle(pdf, "TLS findings")
	drawFindingsTable(pdf, rep.SSL.Findings)
	pdf.Ln(2)

	pdf.AddPage()
	sectionTitle(pdf, "HTTP security headers")
	rowTableWrapped(pdf, httpSummaryHeaders(), httpSummaryValues(rep.HTTP))
	pdf.Ln(2)
	if len(rep.HTTP.Tests) > 0 {
		sectionTitle(pdf, "HTTP header checks")
		drawHTTPTestsTable(pdf, rep.HTTP.Tests)
		pdf.Ln(2)
	}
	sectionTitle(pdf, "HTTP findings")
	drawFindingsTable(pdf, rep.HTTP.Findings)

	if err := pdf.OutputFileAndClose(out); err != nil {
		return "", err
	}
	return out, nil
}

func drawPDFHeader(pdf *fpdf.Fpdf) {
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(0, 0, pageW, 28, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont(reportFontFamily, "B", 20)
	pdf.SetXY(margin, 7)
	pdf.CellFormat(0, 7, "Recordscan Security Report", "", 1, "L", false, 0, "")
	pdf.SetFont(reportFontFamily, "", 10)
	pdf.SetX(margin)
	pdf.CellFormat(0, 5, "DNS, TLS, and HTTP Response Header Audit", "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.SetY(32)
	pdf.Ln(2)
}

func sectionTitle(pdf *fpdf.Fpdf, s string) {
	ensureSpace(pdf, 14)
	pdf.SetFont(reportFontFamily, "B", 12)
	pdf.SetTextColor(17, 24, 39)
	pdf.CellFormat(0, 7, sanitizePDF(s), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

func rowTableWrapped(pdf *fpdf.Fpdf, headers, values []string) {
	if len(headers) == 0 || len(headers) != len(values) {
		return
	}
	n := len(headers)
	cellW := bodyW / float64(n)
	w := make([]float64, n)
	for i := range w {
		w[i] = cellW
	}
	wrappedTableHeader(pdf, w, headers)
	wrappedTableRow(pdf, w, values, rowAlignCenter(n), 17, 24, 39)
}

func summaryHeaders() []string {
	return []string{
		"Findings", "DNS", "TLS", "HTTP", "HTTP OK", "TLS grade", "Proto", "Cert",
	}
}

func summaryValues(rep model.ScanReport) []string {
	s := rep.Summary
	totalHTTP := s.HTTPTestsPassed + s.HTTPTestsFailed
	return []string{
		fmt.Sprintf("%d", s.FindingsTotal),
		fmt.Sprintf("%d", s.DNSFindingCount),
		fmt.Sprintf("%d", s.SSLFindingCount),
		fmt.Sprintf("%d", s.HTTPFindingCount),
		fmt.Sprintf("%d/%d", s.HTTPTestsPassed, totalHTTP),
		s.SSLGrade,
		fmt.Sprintf("%d", s.SSLProtocolScore),
		fmt.Sprintf("%d", s.SSLCertificateScore),
	}
}

func severityRow(rep model.ScanReport) string {
	if len(rep.Summary.BySeverity) == 0 {
		return ""
	}
	keys := make([]string, 0, len(rep.Summary.BySeverity))
	for k := range rep.Summary.BySeverity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%d", k, rep.Summary.BySeverity[k])
	}
	return b.String()
}

func drawDNSRecordsTable(pdf *fpdf.Fpdf, d model.DNSReport) {
	if len(d.RawRecords) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(100, 116, 139)
		pdf.MultiCell(0, 5, "No DNS record map captured.", "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		return
	}
	types := []string{"A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA", "CNAME", "DMARC", "DKIM_default"}
	var rows [][2]string
	for _, t := range types {
		vals, ok := d.RawRecords[t]
		if !ok || len(vals) == 0 {
			continue
		}
		joined := strings.Join(vals, " | ")
		rows = append(rows, [2]string{t, joined})
	}
	if len(rows) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.MultiCell(0, 5, "No records in standard set.", "", "L", false)
		return
	}
	w := []float64{28, bodyW - 28}
	wrappedTableHeader(pdf, w, []string{"Record", "Value"})
	for _, row := range rows {
		ensureSpace(pdf, 16)
		wrappedTableRow(pdf, w, []string{row[0], row[1]}, rowAlignLeft(2), 17, 24, 39)
	}
}

func drawFindingsTable(pdf *fpdf.Fpdf, ff []model.Finding) {
	if len(ff) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(22, 135, 75)
		pdf.MultiCell(0, 5, "None. No findings in this section.", "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		return
	}
	w := []float64{22, 32, 50, 82}
	wrappedTableHeader(pdf, w, []string{"Severity", "Category", "Title", "Detail / fix"})
	for _, f := range ff {
		ensureSpace(pdf, 14)
		detail := f.Detail
		if f.Recommendation != "" {
			detail = detail + " Fix: " + f.Recommendation
		}
		tr, tg, tb := issueRowRGB(f.Severity)
		wrappedTableRow(pdf, w, []string{
			strings.ToUpper(strings.TrimSpace(f.Severity)),
			f.Category,
			f.Title,
			detail,
		}, rowAlignLeft(4), tr, tg, tb)
	}
}

func tlsSummaryHeaders() []string {
	return []string{"Host", "Port", "Connected", "Version", "Cipher", "Grade", "Score"}
}

func tlsSummaryValues(s model.SSLReport) []string {
	grade, score := "-", "-"
	if s.Grading != nil {
		grade = s.Grading.OverallGrade
		score = fmt.Sprintf("%d", s.Grading.OverallScore)
	}
	conn := "no"
	if s.Connected {
		conn = "yes"
	}
	return []string{
		s.Host,
		fmt.Sprintf("%d", s.Port),
		conn,
		s.NegotiatedVersion,
		s.NegotiatedCipher,
		grade,
		score,
	}
}

func certHeaders() []string {
	return []string{"Subject CN", "Issuer", "Not after (UTC)", "Days left", "Sig alg", "Verified", "SAN match"}
}

func certValues(c *model.CertificateSummary) []string {
	if c == nil {
		return nil
	}
	return []string{
		c.SubjectCN,
		c.IssuerCN,
		c.NotAfterUTC,
		fmt.Sprintf("%d", c.DaysUntilExpiry),
		c.SignatureAlgorithm,
		fmt.Sprintf("%v", c.VerifiedChain),
		fmt.Sprintf("%v", c.HostnameMatch),
	}
}

func drawCipherTable(pdf *fpdf.Fpdf, suites []model.CipherProbe) {
	max := len(suites)
	if max > 45 {
		max = 45
	}
	w := []float64{95, 28, 22, 41}
	wrappedTableHeader(pdf, w, []string{"Cipher suite", "Protocol", "Score", "ID"})
	for i := 0; i < max; i++ {
		c := suites[i]
		ensureSpace(pdf, 12)
		r, g, b := cipherScoreRGB(c.Score)
		wrappedTableRow(pdf, w, []string{
			c.Name,
			c.Protocol,
			fmt.Sprintf("%d", c.Score),
			fmt.Sprintf("%d", c.ID),
		}, []string{"L", "C", "C", "C"}, r, g, b)
	}
	if len(suites) > max {
		pdf.SetFont(reportFontFamily, "I", 8)
		pdf.MultiCell(0, 5, sanitizePDF(fmt.Sprintf("Plus %d more cipher suites (see scan.json).", len(suites)-max)), "", "L", false)
	}
}

func httpSummaryHeaders() []string {
	return []string{"Base URL", "Status", "Final URL", "Error"}
}

func httpSummaryValues(h model.HTTPReport) []string {
	err := h.Error
	if err == "" {
		err = "-"
	}
	return []string{
		h.BaseURL,
		fmt.Sprintf("%d", h.StatusCode),
		h.FinalURL,
		err,
	}
}

func drawHTTPTestsTable(pdf *fpdf.Fpdf, tests []model.HTTPTest) {
	w := []float64{22, 78, 86}
	wrappedTableHeader(pdf, w, []string{"Result", "Check", "Detail"})
	for _, t := range tests {
		ensureSpace(pdf, 12)
		st := "FAIL"
		if t.Skipped {
			st = "SKIP"
		} else if t.Passed {
			st = "PASS"
		}
		tr, tg, tb := httpResultRGB(t.Passed, t.Skipped)
		wrappedTableRow(pdf, w, []string{st, t.Name, t.Detail}, []string{"C", "L", "L"}, tr, tg, tb)
	}
}

// pageSafeY: start a new page before content would cross this Y (A4 ~285mm usable with12mm bottom margin).
const pageSafeY = 278.0

func ensureSpace(pdf *fpdf.Fpdf, needMM float64) {
	if pdf.GetY()+needMM > pageSafeY {
		pdf.AddPage()
	}
}
