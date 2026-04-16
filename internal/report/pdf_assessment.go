package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-pdf/fpdf"

	"recordscan/internal/model"
)

// drawAssessmentOverview prints wrong vs right summary and three prioritized actions.
func drawAssessmentOverview(pdf *fpdf.Fpdf, rep model.ScanReport) {
	ensureSpace(pdf, 55)
	sectionTitle(pdf, "Assessment overview")

	wrong := buildWrongSummary(rep)
	right := buildRightSummary(rep)
	tips := topRecommendations(rep, 3)

	pdf.SetFont(reportFontFamily, "B", 9)
	pdf.SetTextColor(185, 28, 28)
	pdf.MultiCell(0, 5, "Needs attention", "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.MultiCell(0, 4, sanitizePDF(wrong), "", "L", false)
	pdf.Ln(1)

	pdf.SetFont(reportFontFamily, "B", 9)
	pdf.SetTextColor(22, 135, 75)
	pdf.MultiCell(0, 5, "In good shape", "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.MultiCell(0, 4, sanitizePDF(right), "", "L", false)
	pdf.Ln(2)

	pdf.SetTextColor(17, 24, 39)
	pdf.SetFont(reportFontFamily, "B", 9)
	pdf.MultiCell(0, 5, "Priority actions", "", "L", false)
	pdf.SetFont(reportFontFamily, "", 8)
	for i, t := range tips {
		line := fmt.Sprintf("%d. %s", i+1, sanitizePDF(t))
		pdf.MultiCell(0, 4, line, "", "L", false)
	}
	pdf.Ln(1)
	pdf.SetTextColor(0, 0, 0)
}

func buildWrongSummary(rep model.ScanReport) string {
	s := rep.Summary
	var parts []string
	if s.FindingsTotal > 0 {
		parts = append(parts, fmt.Sprintf("%d total findings across DNS, TLS, and HTTP.", s.FindingsTotal))
	}
	ch := s.BySeverity["critical"] + s.BySeverity["high"] + s.BySeverity["medium"]
	if ch > 0 {
		parts = append(parts, fmt.Sprintf("%d are critical, high, or medium severity.", ch))
	}
	if s.HTTPTestsFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d HTTP security header checks failed.", s.HTTPTestsFailed))
	}
	if rep.SSL.Error != "" {
		parts = append(parts, "TLS could not be fully assessed: "+rep.SSL.Error)
	} else if rep.SSL.Grading != nil {
		g := rep.SSL.Grading.OverallGrade
		if g == "F" || g == "D" || strings.HasPrefix(g, "D") {
			parts = append(parts, fmt.Sprintf("TLS overall grade is weak (%s).", g))
		}
	}
	if len(rep.SSL.WeakProtocolsEnabled) > 0 {
		parts = append(parts, "Legacy TLS versions are enabled: "+strings.Join(rep.SSL.WeakProtocolsEnabled, ", "))
	}
	if len(parts) == 0 {
		return "No major issues flagged at summary level. Review detailed tables below."
	}
	return strings.Join(parts, " ")
}

func buildRightSummary(rep model.ScanReport) string {
	s := rep.Summary
	var parts []string
	if s.HTTPTestsPassed > 0 {
		tot := s.HTTPTestsPassed + s.HTTPTestsFailed
		parts = append(parts, fmt.Sprintf("%d of %d HTTP header checks passed.", s.HTTPTestsPassed, tot))
	}
	if rep.SSL.Grading != nil {
		g := rep.SSL.Grading.OverallGrade
		if g == "A" || g == "A+" || g == "B" {
			parts = append(parts, fmt.Sprintf("TLS grade %s with negotiated %s.", g, rep.SSL.NegotiatedVersion))
		}
	}
	if rep.SSL.Certificate != nil && rep.SSL.Certificate.VerifiedChain && rep.SSL.Certificate.DaysUntilExpiry > 30 {
		parts = append(parts, fmt.Sprintf("Certificate verified; about %d days until expiry.", rep.SSL.Certificate.DaysUntilExpiry))
	}
	if len(rep.DNS.Nameservers) >= 2 {
		parts = append(parts, fmt.Sprintf("DNS has %d nameservers (redundancy OK).", len(rep.DNS.Nameservers)))
	}
	if len(parts) == 0 {
		return "See detailed sections for positive signals."
	}
	return strings.Join(parts, " ")
}

func topRecommendations(rep model.ScanReport, n int) []string {
	type ranked struct {
		sev int
		rec string
	}
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}
	var cands []ranked
	add := func(ff []model.Finding) {
		for _, f := range ff {
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
	}
	add(rep.DNS.Findings)
	add(rep.SSL.Findings)
	add(rep.HTTP.Findings)
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].sev != cands[j].sev {
			return cands[i].sev < cands[j].sev
		}
		return cands[i].rec < cands[j].rec
	})
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
		"Address high-severity DNS and TLS findings first, then HTTP headers.",
		"Re-run recordscan after changes to confirm findings decrease.",
		"Archive scan.json and this PDF for audit history and trending.",
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
	if len(out) > n {
		out = out[:n]
	}
	return out
}
