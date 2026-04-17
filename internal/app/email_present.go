package app

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	lgtable "github.com/charmbracelet/lipgloss/table"

	"recordscan/internal/model"
	"recordscan/internal/output"
)

// PrintEmailSummary prints lipgloss summary for email assessment.
func PrintEmailSummary(rep model.EmailSecReport, paths output.Paths) {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("recordscan email security")
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24")).Padding(0, 1)
	cellStyle := lipgloss.NewStyle().Padding(0, 1)
	oddRowStyle := lipgloss.NewStyle().Background(lipgloss.Color("236"))

	sev := severitySummary(rep.Summary.BySeverity)

	rows := [][]string{
		{"Zone", rep.Zone},
		{"Posture", fmt.Sprintf("%s (%d/100)", rep.Summary.PostureLabel, rep.Summary.PostureScore)},
		{"Controls", fmt.Sprintf("pass=%d warn=%d fail=%d", rep.Summary.ControlsPass, rep.Summary.ControlsWarn, rep.Summary.ControlsFail)},
		{"Findings (total)", fmt.Sprintf("%d", rep.Summary.FindingsTotal)},
		{"Severity breakdown", sev},
		{"MX hosts", fmt.Sprintf("%d", rep.Summary.MXCount)},
		{"DKIM selectors (hits)", fmt.Sprintf("%d / %d probed", rep.Summary.DKIMPublishers, len(rep.DKIM))},
		{"SPF", fmt.Sprintf("%v", rep.Summary.HasSPF)},
		{"DMARC", fmt.Sprintf("%v", rep.Summary.HasDMARC)},
		{"MTA-STS policy OK", fmt.Sprintf("%v", rep.Summary.MTASTSEnabled)},
		{"TLS-RPT", fmt.Sprintf("%v", rep.Summary.TLSRPTPublished)},
		{"email-sec-scan.json", paths.ScanJSON},
		{"Email PDF report", paths.PDF},
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
