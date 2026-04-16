package util

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseTarget returns host, port for TLS (default 443 for https), and origin URL (scheme://host[:port]) for HTTP checks.
func ParseTarget(raw string) (host string, tlsPort int, baseURL string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 443, ""
	}
	tlsPort = 443
	scheme := "https"

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			h := stripHost(raw)
			return h, 443, "https://" + h
		}
		host = stripHost(u.Hostname())
		if u.Scheme == "http" {
			scheme = "http"
		}
		if p := u.Port(); p != "" {
			if np, err := strconv.Atoi(p); err == nil && np > 0 {
				tlsPort = np
			}
		} else if scheme == "http" {
			tlsPort = 80
		}
		return host, tlsPort, originURL(scheme, host, tlsPort)
	}

	if h, p, err := net.SplitHostPort(raw); err == nil {
		host = stripHost(h)
		if np, err := strconv.Atoi(p); err == nil && np > 0 {
			tlsPort = np
		}
		return host, tlsPort, originURL(scheme, host, tlsPort)
	}

	host = stripHost(raw)
	return host, tlsPort, originURL(scheme, host, tlsPort)
}

func originURL(scheme, host string, port int) string {
	if host == "" {
		return ""
	}
	if scheme == "http" && port == 80 {
		return "http://" + host
	}
	if scheme == "https" && port == 443 {
		return "https://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func stripHost(s string) string {
	return strings.Trim(strings.TrimSpace(strings.ToLower(s)), ".")
}
