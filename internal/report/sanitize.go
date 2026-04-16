package report

import "strings"

// sanitizePDF normalizes text for PDF output (avoids mojibake when core fonts are used; UTF-8 TTFs still benefit).
func sanitizePDF(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(
		"\r\n", " ",
		"\n", " ",
		"\r", " ",
		"\u2014", "-", // em dash
		"\u2013", "-", // en dash
		"\u2026", "...", // ellipsis
		"\u2265", ">=", // greater-than or equal
		"\u2264", "<=",
		"\u00a0", " ",
		"\u201c", `"`,
		"\u201d", `"`,
		"\u2018", "'",
		"\u2019", "'",
		"\u00b7", "-", // middle dot
		"\u2022", "-", // bullet
	)
	s = r.Replace(s)
	var out strings.Builder
	out.Grow(len(s))
	for _, c := range s {
		switch {
		case c >= 32 && c <= 126:
			out.WriteRune(c)
		case c == '\t':
			out.WriteByte(' ')
		default:
			// drop remaining non-ASCII after replacements
		}
	}
	return strings.TrimSpace(out.String())
}

func trimPDFText(s string, max int) string {
	s = sanitizePDF(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
