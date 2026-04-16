package report

import (
	"strings"

	"github.com/go-pdf/fpdf"
)

const (
	wrapLineHt = 4.0
	cellPad    = 1.2
)

// wrappedTableHeader draws a single-line header row (navy).
func wrappedTableHeader(pdf *fpdf.Fpdf, w []float64, headers []string) {
	ensureSpace(pdf, 10)
	auto, breakM := pdf.GetAutoPageBreak()
	pdf.SetAutoPageBreak(false, 0)
	pdf.SetX(margin)
	pdf.SetFont(reportFontFamily, "B", 8)
	pdf.SetFillColor(30, 41, 59)
	pdf.SetTextColor(255, 255, 255)
	y := pdf.GetY()
	x := margin
	for i, h := range headers {
		pdf.SetXY(x, y)
		pdf.CellFormat(w[i], 7, sanitizePDF(h), "1", 0, "C", true, 0, "")
		x += w[i]
	}
	pdf.SetXY(margin, y+7)
	pdf.SetFont(reportFontFamily, "", 8)
	pdf.SetAutoPageBreak(auto, breakM)
}

// wrappedTableRow draws one data row with word-wrapped cells; sets text color RGB then resets black.
func wrappedTableRow(pdf *fpdf.Fpdf, w []float64, texts []string, aligns []string, tr, tg, tb int) {
	if len(w) != len(texts) {
		return
	}
	if len(aligns) < len(w) {
		na := make([]string, len(w))
		copy(na, aligns)
		for i := len(aligns); i < len(w); i++ {
			na[i] = "L"
		}
		aligns = na
	}

	type cell struct {
		lines [][]byte
		ht    float64
	}
	cells := make([]cell, len(w))
	maxHt := wrapLineHt
	for i, t := range texts {
		inner := w[i] - 2*cellPad
		if inner < 8 {
			inner = 8
		}
		raw := sanitizePDF(t)
		list := pdf.SplitLines([]byte(raw), inner)
		if len(list) == 0 {
			list = [][]byte{[]byte("")}
		}
		ht := float64(len(list)) * wrapLineHt
		if ht < wrapLineHt {
			ht = wrapLineHt
		}
		cells[i] = cell{list, ht}
		if ht > maxHt {
			maxHt = ht
		}
	}
	rowH := maxHt + 2*cellPad
	ensureSpace(pdf, rowH+10)

	auto, breakM := pdf.GetAutoPageBreak()
	pdf.SetAutoPageBreak(false, 0)

	y0 := pdf.GetY()
	x := margin

	pdf.SetDrawColor(100, 116, 139)
	pdf.SetTextColor(tr, tg, tb)
	for i := range w {
		pdf.Rect(x, y0, w[i], rowH, "D")
		cy := y0 + cellPad + (maxHt-cells[i].ht)/2
		for _, line := range cells[i].lines {
			pdf.SetXY(x+cellPad, cy)
			pdf.CellFormat(w[i]-2*cellPad, wrapLineHt, string(line), "", 0, aligns[i], false, 0, "")
			cy += wrapLineHt
		}
		x += w[i]
	}
	pdf.SetY(y0 + rowH)
	pdf.SetX(margin)
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetTextColor(0, 0, 0)

	pdf.SetAutoPageBreak(auto, breakM)
}

func rowAlignCenter(n int) []string {
	a := make([]string, n)
	for i := range a {
		a[i] = "C"
	}
	return a
}

func rowAlignLeft(n int) []string {
	a := make([]string, n)
	for i := range a {
		a[i] = "L"
	}
	return a
}

// issueRowRGB returns text color: problems red, informational amber, pass/good green.
func issueRowRGB(severity string) (r, g, b int) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "pass":
		return 22, 135, 75 // green
	case "low":
		return 56, 189, 248 // light blue
	case "info":
		return 180, 83, 9 // amber (informational)
	default:
		return 185, 28, 28 // red
	}
}

func httpResultRGB(passed, skipped bool) (r, g, b int) {
	if skipped {
		return 100, 116, 139
	}
	if passed {
		return 22, 135, 75
	}
	return 185, 28, 28
}

func cipherScoreRGB(score int) (r, g, b int) {
	if score >= 80 {
		return 22, 135, 75
	}
	if score >= 60 {
		return 180, 83, 9
	}
	return 185, 28, 28
}
