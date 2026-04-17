package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-pdf/fpdf"

	"recordscan/internal/model"
)

// WriteEmailPDF writes recordscan-email-report.pdf (email authentication & transport assessment).
func WriteEmailPDF(baseDir string, rep model.EmailSecReport) (string, error) {
	out := filepath.Join(baseDir, "recordscan-email-report.pdf")
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin)
	reportFontFamily = configureReportFont(pdf)
	pdf.AddPage()
	pdf.SetTitle("Recordscan Email Security Assessment", false)
	pdf.SetAuthor("recordscan", false)

	drawEmailCoverHeader(pdf, rep)
	drawEmailPostureCard(pdf, rep)
	drawEmailExecutiveNarrative(pdf, rep)
	pdf.Ln(3)

	emailSectionTitle(pdf, "Control compliance matrix")
	drawEmailControlsTable(pdf, rep.Controls)
	pdf.Ln(2)

	emailSectionTitle(pdf, "Inbound mail routing (MX)")
	drawEmailMXTable(pdf, rep.MX)
	pdf.Ln(2)

	emailSectionTitle(pdf, "Sender Policy Framework (SPF)")
	drawEmailSPFBlock(pdf, rep.SPF)
	pdf.Ln(2)

	emailSectionTitle(pdf, "Domain-based Message Authentication (DMARC)")
	drawEmailDMARCBlock(pdf, rep.DMARC)
	pdf.Ln(2)

	emailSectionTitle(pdf, "DKIM DNS discovery")
	drawEmailDKIMTable(pdf, rep.DKIM)
	pdf.Ln(2)

	pdf.AddPage()
	emailSectionTitle(pdf, "Mail transport security (MTA-STS, TLS-RPT, BIMI)")
	drawEmailTransportBlock(pdf, rep)
	pdf.Ln(2)

	emailSectionTitle(pdf, "Detailed findings")
	drawFindingsTable(pdf, rep.Findings)
	pdf.Ln(2)

	emailSectionTitle(pdf, "Prioritized remediation")
	drawEmailRemediation(pdf, rep)

	if err := pdf.OutputFileAndClose(out); err != nil {
		return "", err
	}
	return out, nil
}

func drawEmailCoverHeader(pdf *fpdf.Fpdf, rep model.EmailSecReport) {
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(0, 0, pageW, 36, "F")
	pdf.SetFillColor(14, 165, 233)
	pdf.Rect(0, 36, pageW, 1.2, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont(reportFontFamily, "B", 18)
	pdf.SetXY(margin, 8)
	pdf.CellFormat(0, 8, sanitizePDF("Email Security & Authentication Assessment"), "", 1, "L", false, 0, "")
	pdf.SetFont(reportFontFamily, "", 10)
	pdf.SetX(margin)
	pdf.CellFormat(0, 6, sanitizePDF("Zone: "+rep.Zone), "", 1, "L", false, 0, "")

	pdf.SetTextColor(17, 24, 39)
	pdf.SetY(44)
}

func drawEmailPostureCard(pdf *fpdf.Fpdf, rep model.EmailSecReport) {
	ensureSpace(pdf, 38)
	s := rep.Summary
	r, g, b := postureRGB(s.PostureLabel)

	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(203, 213, 225)
	pdf.RoundedRect(margin, pdf.GetY(), bodyW, 28, 2, "1234", "DF")
	y0 := pdf.GetY()

	pdf.SetFillColor(r, g, b)
	pdf.RoundedRect(margin+2, y0+2, 42, 24, 1.5, "1234", "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(margin+4, y0+6)
	pdf.SetFont(reportFontFamily, "B", 14)
	pdf.CellFormat(38, 8, sanitizePDF(s.PostureLabel), "", 1, "C", false, 0, "")
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.SetX(margin + 4)
	pdf.CellFormat(38, 4, sanitizePDF(fmt.Sprintf("Score %d/100", s.PostureScore)), "", 1, "C", false, 0, "")

	pdf.SetTextColor(15, 23, 42)
	pdf.SetXY(margin+50, y0+4)
	pdf.SetFont(reportFontFamily, "B", 9)
	pdf.CellFormat(0, 5, sanitizePDF("Control snapshot"), "", 1, "L", false, 0, "")
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.SetX(margin + 50)
	line := fmt.Sprintf("Pass %d   Warn %d   Fail %d   |   Findings %d   |   MX %d   |   DKIM hits %d",
		s.ControlsPass, s.ControlsWarn, s.ControlsFail, s.FindingsTotal, s.MXCount, s.DKIMPublishers)
	pdf.MultiCell(bodyW-52, 4, sanitizePDF(line), "", "L", false)
	pdf.SetY(y0 + 30)
	pdf.SetTextColor(0, 0, 0)
}

func postureRGB(label string) (r, g, b int) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "strong":
		return 22, 135, 75
	case "moderate":
		return 180, 83, 9
	case "weak":
		return 194, 65, 12
	case "critical risk":
		return 185, 28, 28
	default:
		return 100, 116, 139
	}
}

func drawEmailExecutiveNarrative(pdf *fpdf.Fpdf, rep model.EmailSecReport) {
	ensureSpace(pdf, 42)
	wrong := buildEmailWrong(rep)
	right := buildEmailRight(rep)
	tips := emailRemediationList(rep, 4)

	pdf.SetFont(reportFontFamily, "B", 10)
	pdf.SetTextColor(185, 28, 28)
	pdf.MultiCell(0, 5, sanitizePDF("Gaps and risks"), "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.SetTextColor(71, 85, 105)
	pdf.MultiCell(0, 4, sanitizePDF(wrong), "", "L", false)
	pdf.Ln(1)

	pdf.SetFont(reportFontFamily, "B", 10)
	pdf.SetTextColor(22, 135, 75)
	pdf.MultiCell(0, 5, sanitizePDF("What is working"), "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.MultiCell(0, 4, sanitizePDF(right), "", "L", false)
	pdf.Ln(1)

	pdf.SetTextColor(17, 24, 39)
	pdf.SetFont(reportFontFamily, "B", 10)
	pdf.MultiCell(0, 5, sanitizePDF("Executive actions"), "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	for i, t := range tips {
		pdf.MultiCell(0, 4, sanitizePDF(fmt.Sprintf("%d. %s", i+1, t)), "", "L", false)
	}
	pdf.SetTextColor(0, 0, 0)
}

func buildEmailWrong(rep model.EmailSecReport) string {
	var parts []string
	for _, c := range rep.Controls {
		if strings.ToLower(c.Status) == "fail" {
			parts = append(parts, c.Title+": "+strings.TrimSpace(c.Detail))
		}
	}
	ch := rep.Summary.BySeverity["critical"] + rep.Summary.BySeverity["high"]
	if ch > 0 {
		parts = append(parts, fmt.Sprintf("%d critical/high findings in the detailed table.", ch))
	}
	if len(parts) == 0 {
		return "No failed controls at matrix level. Review warnings and informational findings below."
	}
	return strings.Join(parts, " ")
}

func buildEmailRight(rep model.EmailSecReport) string {
	var parts []string
	for _, c := range rep.Controls {
		if strings.ToLower(c.Status) == "pass" {
			parts = append(parts, c.Title)
		}
	}
	if len(parts) > 6 {
		parts = parts[:6]
		parts = append(parts, "...")
	}
	if len(parts) == 0 {
		return "Limited positive controls detected; prioritize SPF, DMARC, and DKIM alignment."
	}
	return strings.Join(parts, "; ") + "."
}

func emailRemediationList(rep model.EmailSecReport, n int) []string {
	type ranked struct {
		sev int
		rec string
	}
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	var cands []ranked
	for _, f := range rep.Findings {
		r := strings.TrimSpace(f.Recommendation)
		if r == "" {
			continue
		}
		o := 99
		if v, ok := order[strings.ToLower(f.Severity)]; ok {
			o = v
		}
		cands = append(cands, ranked{o, r})
	}
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[j].sev < cands[i].sev {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, c := range cands {
		if len(out) >= n {
			break
		}
		if _, ok := seen[c.rec]; ok {
			continue
		}
		seen[c.rec] = struct{}{}
		out = append(out, c.rec)
	}
	defaults := []string{
		"Resolve failed controls in the compliance matrix first, then tighten warn-level items.",
		"Validate changes in a staging DNS view before production cutover.",
		"Re-run recordscan email after DNS TTL expiry to confirm propagation.",
	}
	for _, d := range defaults {
		if len(out) >= n {
			break
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func emailSectionTitle(pdf *fpdf.Fpdf, s string) {
	ensureSpace(pdf, 14)
	pdf.SetFillColor(241, 245, 249)
	pdf.SetDrawColor(203, 213, 225)
	pdf.RoundedRect(margin, pdf.GetY(), bodyW, 8, 1, "1234", "F")
	pdf.SetXY(margin+3, pdf.GetY()+1.5)
	pdf.SetFont(reportFontFamily, "B", 11)
	pdf.SetTextColor(30, 41, 59)
	pdf.CellFormat(0, 6, sanitizePDF(s), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

func drawEmailControlsTable(pdf *fpdf.Fpdf, rows []model.EmailControl) {
	if len(rows) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.MultiCell(0, 5, "No controls computed.", "", "L", false)
		return
	}
	w := []float64{30, 64, 24, 68}
	wrappedTableHeader(pdf, w, []string{"Area", "Control", "Status", "Detail"})
	for _, c := range rows {
		ensureSpace(pdf, 14)
		st := strings.ToUpper(c.Status)
		tr, tg, tb := controlRowRGB(c.Status)
		wrappedTableRow(pdf, w, []string{
			c.Area,
			c.Title,
			st,
			c.Detail,
		}, []string{"L", "L", "C", "L"}, tr, tg, tb)
	}
}

func controlRowRGB(status string) (r, g, b int) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass":
		return 22, 135, 75
	case "warn":
		return 180, 83, 9
	default:
		return 185, 28, 28
	}
}

func drawEmailMXTable(pdf *fpdf.Fpdf, mx []model.EmailMXRow) {
	if len(mx) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(100, 116, 139)
		pdf.MultiCell(0, 5, "No MX records returned for the zone apex.", "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		return
	}
	w := []float64{18, 62, 52, 54}
	wrappedTableHeader(pdf, w, []string{"Pri", "Mail exchanger", "A records", "Notes"})
	for _, m := range mx {
		ensureSpace(pdf, 14)
		res := strings.Join(m.Resolved, ", ")
		if res == "" {
			res = "-"
		}
		note := m.Notes
		if note == "" {
			note = "-"
		}
		wrappedTableRow(pdf, w, []string{
			fmt.Sprintf("%d", m.Priority),
			m.Host,
			res,
			note,
		}, rowAlignLeft(4), 17, 24, 39)
	}
}

func drawEmailSPFBlock(pdf *fpdf.Fpdf, spf *model.EmailSPFSection) {
	if spf == nil || len(spf.RawRecords) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.MultiCell(0, 5, "No SPF TXT record detected at the apex.", "", "L", false)
		return
	}
	w := []float64{40, bodyW - 40}
	wrappedTableHeader(pdf, w, []string{"Attribute", "Value"})
	rows := [][2]string{
		{"SPF record(s)", strings.Join(spf.RawRecords, " | ")},
		{"Estimated DNS lookups", fmt.Sprintf("%d", spf.LookupEstimate)},
		{"Lookup notes", spf.LookupDetail},
		{"All mechanism", spf.EndsWithAll},
		{"Uses ptr", fmt.Sprintf("%v", spf.HasPTR)},
		{"Redirect", spf.RedirectTarget},
	}
	for _, row := range rows {
		if strings.TrimSpace(row[1]) == "" && row[0] != "SPF record(s)" {
			continue
		}
		ensureSpace(pdf, 12)
		wrappedTableRow(pdf, w, []string{row[0], row[1]}, rowAlignLeft(2), 17, 24, 39)
	}
}

func drawEmailDMARCBlock(pdf *fpdf.Fpdf, d *model.EmailDMARCSection) {
	if d == nil || len(d.RawRecords) == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.MultiCell(0, 5, "No DMARC record at _dmarc.", "", "L", false)
		return
	}
	w := []float64{38, bodyW - 38}
	wrappedTableHeader(pdf, w, []string{"Tag / field", "Value"})
	pairs := [][2]string{
		{"Raw record", strings.Join(d.RawRecords, " | ")},
		{"p (policy)", d.Policy},
		{"sp (subdomain)", d.Subpolicy},
		{"pct", d.Pct},
		{"rua", d.RUA},
		{"ruf", d.RUF},
		{"adkim", d.ADKIM},
		{"aspf", d.ASPF},
	}
	for _, p := range pairs {
		if strings.TrimSpace(p[1]) == "" && p[0] != "Raw record" {
			continue
		}
		ensureSpace(pdf, 12)
		wrappedTableRow(pdf, w, []string{p[0], p[1]}, rowAlignLeft(2), 17, 24, 39)
	}
}

func drawEmailDKIMTable(pdf *fpdf.Fpdf, rows []model.EmailDKIMRow) {
	found := 0
	for _, d := range rows {
		if d.Found {
			found++
		}
	}
	pdf.SetFont(reportFontFamily, "I", 8)
	pdf.MultiCell(0, 4, sanitizePDF(fmt.Sprintf("Probed %d common selectors. Matches: %d.", len(rows), found)), "", "L", false)
	pdf.Ln(1)

	w := []float64{36, 18, bodyW - 54}
	wrappedTableHeader(pdf, w, []string{"Selector", "Found", "Record / notes"})
	shown := 0
	for _, d := range rows {
		if !d.Found {
			continue
		}
		ensureSpace(pdf, 14)
		rec := strings.Join(d.Records, " | ")
		if d.Notes != "" {
			rec = rec + " — " + d.Notes
		}
		wrappedTableRow(pdf, w, []string{
			d.Selector,
			"yes",
			rec,
		}, rowAlignLeft(3), 17, 24, 39)
		shown++
	}
	if shown == 0 {
		pdf.SetFont(reportFontFamily, "", 9)
		pdf.SetTextColor(185, 28, 28)
		pdf.MultiCell(0, 5, "No DKIM TXT matched common selectors. Publish keys for your active MTA selectors.", "", "L", false)
		pdf.SetTextColor(0, 0, 0)
	}
}

func drawEmailTransportBlock(pdf *fpdf.Fpdf, rep model.EmailSecReport) {
	w := []float64{44, bodyW - 44}
	wrappedTableHeader(pdf, w, []string{"Control", "Details"})

	if rep.MTASTS != nil {
		ensureSpace(pdf, 16)
		detail := rep.MTASTS.TXTRecord
		if rep.MTASTS.PolicyURL != "" {
			detail += "\nPolicy URL: " + rep.MTASTS.PolicyURL
		}
		if rep.MTASTS.Mode != "" {
			detail += "\nMode: " + rep.MTASTS.Mode + "  max_age: " + rep.MTASTS.MaxAge
		}
		if rep.MTASTS.MXPatterns != "" {
			detail += "\nMX patterns: " + rep.MTASTS.MXPatterns
		}
		if rep.MTASTS.PolicyFetch != "" {
			detail += "\nFetch error: " + rep.MTASTS.PolicyFetch
		} else if rep.MTASTS.PolicyBody != "" {
			snippet := rep.MTASTS.PolicyBody
			if len(snippet) > 400 {
				snippet = snippet[:400] + "..."
			}
			detail += "\nPolicy excerpt:\n" + snippet
		}
		wrappedTableRow(pdf, w, []string{"MTA-STS", detail}, rowAlignLeft(2), 17, 24, 39)
	} else {
		ensureSpace(pdf, 10)
		wrappedTableRow(pdf, w, []string{"MTA-STS", "Not configured (_mta-sts TXT missing)."}, rowAlignLeft(2), 17, 24, 39)
	}

	if rep.TLSRPT != nil {
		ensureSpace(pdf, 12)
		d := rep.TLSRPT.TXTRecord
		if rep.TLSRPT.RUA != "" {
			d += "\nrua: " + rep.TLSRPT.RUA
		}
		wrappedTableRow(pdf, w, []string{"TLS-RPT (_smtp._tls)", d}, rowAlignLeft(2), 17, 24, 39)
	} else {
		ensureSpace(pdf, 10)
		wrappedTableRow(pdf, w, []string{"TLS-RPT", "No _smtp._tls TXT."}, rowAlignLeft(2), 17, 24, 39)
	}

	if rep.BIMI != nil {
		ensureSpace(pdf, 12)
		b := rep.BIMI.TXTRecord
		if rep.BIMI.Notes != "" {
			b += "\n" + rep.BIMI.Notes
		}
		wrappedTableRow(pdf, w, []string{"BIMI (default._bimi)", b}, rowAlignLeft(2), 17, 24, 39)
	} else {
		ensureSpace(pdf, 10)
		wrappedTableRow(pdf, w, []string{"BIMI", "Optional record not present."}, rowAlignLeft(2), 100, 116, 139)
	}
}

func drawEmailRemediation(pdf *fpdf.Fpdf, rep model.EmailSecReport) {
	tips := emailRemediationList(rep, 6)
	pdf.SetFont(reportFontFamily, "", 9)
	for i, t := range tips {
		pdf.MultiCell(0, 5, sanitizePDF(fmt.Sprintf("%d. %s", i+1, t)), "", "L", false)
	}
}
