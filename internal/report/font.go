package report

import "github.com/go-pdf/fpdf"

const reportMonoFamily = "RecordscanMono"

// reportFontFamily is set by configureReportFont (embedded JetBrains Mono, else Courier).
var reportFontFamily = "Courier"

// configureReportFont registers embedded JetBrains Mono; call before AddPage().
func configureReportFont(pdf *fpdf.Fpdf) string {
	if len(jetBrainsMonoRegular) == 0 {
		return "Courier"
	}
	pdf.AddUTF8FontFromBytes(reportMonoFamily, "", jetBrainsMonoRegular)
	bold := jetBrainsMonoBold
	if len(bold) == 0 {
		bold = jetBrainsMonoRegular
	}
	pdf.AddUTF8FontFromBytes(reportMonoFamily, "B", bold)
	italic := jetBrainsMonoItalic
	if len(italic) == 0 {
		italic = jetBrainsMonoRegular
	}
	pdf.AddUTF8FontFromBytes(reportMonoFamily, "I", italic)
	return reportMonoFamily
}
