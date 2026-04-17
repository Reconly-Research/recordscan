package emailsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func publicResolver() string {
	return "8.8.8.8:53"
}

func fqdn(name string) string {
	return dns.Fqdn(strings.Trim(strings.TrimSpace(name), "."))
}

func exchange(ctx context.Context, c *dns.Client, qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(fqdn(qname), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)
	r, _, err := c.ExchangeContext(ctx, m, publicResolver())
	if err != nil || r == nil {
		return nil
	}
	return r
}

func lookupTXT(ctx context.Context, c *dns.Client, name string) []string {
	r := exchange(ctx, c, name, dns.TypeTXT)
	if r == nil {
		return nil
	}
	var out []string
	for _, a := range append([]dns.RR{}, r.Answer...) {
		if rr, ok := a.(*dns.TXT); ok {
			out = appendUnique(out, strings.Join(rr.Txt, ""))
		}
	}
	return out
}

func lookupMX(ctx context.Context, c *dns.Client, zone string) []string {
	r := exchange(ctx, c, zone, dns.TypeMX)
	if r == nil {
		return nil
	}
	var lines []string
	for _, a := range r.Answer {
		if rr, ok := a.(*dns.MX); ok {
			line := fmt.Sprintf("%d %s", rr.Preference, strings.TrimSuffix(rr.Mx, "."))
			lines = appendUnique(lines, line)
		}
	}
	return lines
}

func lookupA(ctx context.Context, c *dns.Client, host string) []string {
	r := exchange(ctx, c, host, dns.TypeA)
	if r == nil {
		return nil
	}
	var out []string
	for _, a := range r.Answer {
		if rr, ok := a.(*dns.A); ok {
			out = appendUnique(out, rr.A.String())
		}
	}
	return out
}

func appendUnique(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
