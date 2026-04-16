package util

import (
	"strings"
)

func SanitizeFilename(s string) string {
	r := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		" ", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		"#", "_",
	)
	s = r.Replace(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	return s
}
