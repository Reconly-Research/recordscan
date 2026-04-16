package util

import "fmt"

const (
	reset  = "\033[0m"
	purple = "\033[35m"
	yellow = "\033[33m"
	bold   = "\033[1m"
	dim    = "\033[2m"
)

// Banner returns ASCII block art + tagline (same style as domainscan / clientscan).
func Banner() string {
	art := []string{
		`░█▀▄░█▀▀░█▀▀░█▀█░█▀▄░█▀▄░█▀▀░█▀▀░█▀█░█▀█`,
		`░█▀▄░█▀▀░█░░░█░█░█▀▄░█░█░▀▀█░█░░░█▀█░█░█`,
		`░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀░▀░▀░▀░▀`,
	}

	out := "\n" + bold + purple
	for _, line := range art {
		out += line + "\n"
	}
	out += reset + dim + yellow + "DNS, TLS & HTTP security audit..." + reset + "\n"
	return out
}

func PrintBanner() {
	fmt.Print(Banner())
}
