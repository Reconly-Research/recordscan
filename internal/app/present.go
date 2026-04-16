package app

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	lgtable "github.com/charmbracelet/lipgloss/table"

	"recordscan/internal/model"
	"recordscan/internal/output"
)

// PrintSummary renders a lipgloss table with scan metrics and artifact paths (domainscan-style).
func PrintSummary(rep model.ScanReport, paths output.Paths) {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("recordscan summary")
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24")).Padding(0, 1)
	cellStyle := lipgloss.NewStyle().Padding(0, 1)
	oddRowStyle := lipgloss.NewStyle().Background(lipgloss.Color("236"))

	totalHTTP := rep.Summary.HTTPTestsPassed + rep.Summary.HTTPTestsFailed
	sev := severitySummary(rep.Summary.BySeverity)

	rows := [][]string{
		{"Target", rep.Metadata.TargetHost},
		{"Elapsed", rep.Metadata.Elapsed},
		{"Findings (total)", fmt.Sprintf("%d", rep.Summary.FindingsTotal)},
		{"DNS findings", fmt.Sprintf("%d", rep.Summary.DNSFindingCount)},
		{"TLS findings", fmt.Sprintf("%d", rep.Summary.SSLFindingCount)},
		{"HTTP findings", fmt.Sprintf("%d", rep.Summary.HTTPFindingCount)},
		{"TLS grade", rep.Summary.SSLGrade},
		{"TLS protocol score", fmt.Sprintf("%d", rep.Summary.SSLProtocolScore)},
		{"TLS certificate score", fmt.Sprintf("%d", rep.Summary.SSLCertificateScore)},
		{"HTTP checks passed", fmt.Sprintf("%d / %d", rep.Summary.HTTPTestsPassed, totalHTTP)},
		{"HTTP checks skipped", fmt.Sprintf("%d", rep.Summary.HTTPTestsSkipped)},
		{"Severity breakdown", sev},
		{"scan.json", paths.ScanJSON},
		{"PDF report", paths.PDF},
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, title)
	fmt.Fprintln(
		os.Stdout,
		lgtable.New().
			Border(lipgloss.NormalBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
			Headers("Metric", "Value").
			Rows(rows...).
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return headerStyle
				}
				style := cellStyle
				if row%2 == 0 {
					style = style.Inherit(oddRowStyle)
				}
				if col == 0 {
					return style.Bold(true)
				}
				return style
			}),
	)
}

func severitySummary(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	return b.String()
}
