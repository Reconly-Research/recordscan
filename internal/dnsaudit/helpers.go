package dnsaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"recordscan/internal/model"
)

func auditTTL(ttl int) []model.Finding {
	if ttl <= 0 {
		return nil
	}
	if ttl < 60 {
		return []model.Finding{{
			ID:             "dns-ttl-very-low",
			Category:       "dns_configuration",
			Severity:       "low",
			Title:          "Very low DNS TTL",
			Detail:         fmt.Sprintf("Sample TTL %d seconds increases churn and amplification exposure during attacks.", ttl),
			Recommendation: "Use sane minimum TTLs unless you are actively migrating.",
		}}
	}
	if ttl > 86400*7 {
		return []model.Finding{{
			ID:             "dns-ttl-very-high",
			Category:       "dns_configuration",
			Severity:       "info",
			Title:          "Very high DNS TTL",
			Detail:         fmt.Sprintf("Sample TTL %d seconds slows incident response during hijack or migration.", ttl),
			Recommendation: "Balance performance with ability to roll changes quickly.",
		}}
	}
	return nil
}

func auditNSRedundancy(ns []string) []model.Finding {
	if len(ns) < 2 {
		return []model.Finding{{
			ID:             "dns-ns-redundancy",
			Category:       "dns_configuration",
			Severity:       "medium",
			Title:          "Insufficient nameserver diversity",
			Detail:         fmt.Sprintf("Only %d NS records returned.", len(ns)),
			Recommendation: "Use at least two independent NS hosts/providers.",
		}}
	}
	return nil
}

func compareNSAnswers(ctx context.Context, c *dns.Client, zoneFQDN string, nsHosts []string) []model.Finding {
	if len(nsHosts) < 2 {
		return nil
	}
	sets := make([]map[string]struct{}, 0, len(nsHosts))
	for _, nh := range nsHosts {
		ips := resolveNSIPs(ctx, c, nh)
		if len(ips) == 0 {
			continue
		}
		ans := map[string]struct{}{}
		for _, ip := range ips {
			m := new(dns.Msg)
			m.SetQuestion(zoneFQDN, dns.TypeA)
			m.RecursionDesired = false
			r, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(ip, "53"))
			if err != nil || r == nil {
				continue
			}
			tmp := map[string][]string{}
			collectFromMsg(tmp, r)
			for _, a := range tmp["A"] {
				ans[a] = struct{}{}
			}
		}
		if len(ans) > 0 {
			sets = append(sets, ans)
		}
	}
	if len(sets) < 2 {
		return nil
	}
	base := sets[0]
	for _, s := range sets[1:] {
		if !sameSet(base, s) {
			return []model.Finding{{
				ID:             "dns-ns-answer-mismatch",
				Category:       "dns_configuration",
				Severity:       "medium",
				Title:          "Authoritative NS disagree on A answers",
				Detail:         "Different nameservers returned different A record sets for the apex.",
				Recommendation: "Fix zone data replication; mismatches break consistency and can indicate hijack or lame delegation.",
			}}
		}
	}
	return nil
}

func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func resolveNSIPs(ctx context.Context, c *dns.Client, host string) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	r, _, err := c.ExchangeContext(ctx, m, publicResolver())
	if err != nil || r == nil {
		return nil
	}
	tmp := map[string][]string{}
	collectFromMsg(tmp, r)
	return tmp["A"]
}

func tryAXFR(zoneFQDN string, nsHosts []string, timeout time.Duration) []model.Finding {
	z := strings.TrimSuffix(zoneFQDN, ".")
	tr := new(dns.Transfer)
	for _, nh := range nsHosts {
		for _, ip := range resolveNSIPs(context.Background(), &dns.Client{Timeout: timeout}, nh) {
			m := new(dns.Msg)
			m.SetAxfr(z)
			ch, err := tr.In(m, net.JoinHostPort(ip, "53"))
			if err != nil {
				continue
			}
			n := 0
			for env := range ch {
				if env.Error != nil {
					break
				}
				n += len(env.RR)
				if n > 5 {
					return []model.Finding{{
						ID:             "dns-zone-transfer-open",
						Category:       "dns_vulnerabilities",
						Severity:       "critical",
						Title:          "DNS zone transfer (AXFR) appears permitted",
						Detail:         fmt.Sprintf("Received records from %s (%s).", nh, ip),
						Recommendation: "Restrict AXFR to secondary nameservers via TSIG/IP ACLs.",
						Evidence:       []string{nh, ip},
					}}
				}
			}
		}
	}
	return nil
}

func auditDanglingNS(ctx context.Context, c *dns.Client, nsHosts []string) []model.Finding {
	var out []model.Finding
	for _, nh := range nsHosts {
		if len(resolveNSIPs(ctx, c, nh)) == 0 {
			out = append(out, model.Finding{
				ID:             "dns-dangling-ns",
				Category:       "dns_configuration",
				Severity:       "high",
				Title:          "Nameserver hostname does not resolve",
				Detail:         nh,
				Recommendation: "Fix glue/A records for in-bailiwick NS or correct stale delegation.",
				Evidence:       []string{nh},
			})
		}
	}
	return out
}

func auditNSCNAME(ctx context.Context, c *dns.Client, nsHosts []string) []model.Finding {
	var out []model.Finding
	for _, nh := range nsHosts {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(nh), dns.TypeCNAME)
		m.RecursionDesired = true
		r, _, err := c.ExchangeContext(ctx, m, publicResolver())
		if err != nil || r == nil {
			continue
		}
		for _, a := range r.Answer {
			if _, ok := a.(*dns.CNAME); ok {
				out = append(out, model.Finding{
					ID:             "dns-ns-cname",
					Category:       "dns_configuration",
					Severity:       "high",
					Title:          "NS hostname is a CNAME (RFC 1034 violation)",
					Detail:         nh,
					Recommendation: "Use host A/AAAA for nameservers; CNAME at NS host is not valid.",
					Evidence:       []string{nh},
				})
			}
		}
	}
	return out
}

func auditUncommonRecords(ctx context.Context, c *dns.Client, zoneFQDN string) []model.Finding {
	var out []model.Finding
	for _, pair := range []struct {
		typ  uint16
		name string
	}{
		{dns.TypeSSHFP, "SSHFP"},
		{dns.TypeCERT, "CERT"},
		{dns.TypeOPENPGPKEY, "OPENPGPKEY"},
	} {
		if ans := lookupSlice(ctx, c, zoneFQDN, pair.typ); len(ans) > 0 {
			out = append(out, model.Finding{
				ID:             "dns-uncommon-" + strings.ToLower(pair.name),
				Category:       "information_disclosure",
				Severity:       "info",
				Title:          fmt.Sprintf("%s records present", pair.name),
				Detail:         strings.Join(ans, " | "),
				Recommendation: "Ensure these records are intentional and not leaking internal metadata.",
			})
		}
	}
	return out
}

func auditTXT(records []string) []model.Finding {
	var out []model.Finding
	for _, t := range records {
		if len(t) > 4000 {
			out = append(out, model.Finding{
				ID:             "dns-txt-large",
				Category:       "attack_surface",
				Severity:       "low",
				Title:          "Unusually large TXT record",
				Detail:         fmt.Sprintf("%d characters", len(t)),
				Recommendation: "Large TXT payloads can indicate tunneling; validate legitimacy.",
			})
			break
		}
	}
	return out
}

func auditThirdPartyTXT(records []string) []model.Finding {
	var markers []string
	for _, t := range records {
		low := strings.ToLower(t)
		switch {
		case strings.Contains(low, "google-site-verification="):
			markers = append(markers, "Google site verification")
		case strings.Contains(low, "facebook-domain-verification="):
			markers = append(markers, "Facebook domain verification")
		case strings.Contains(low, "apple-domain-verification="):
			markers = append(markers, "Apple domain verification")
		case strings.Contains(low, "ms="):
			markers = append(markers, "Microsoft verification")
		case strings.Contains(low, "docusign="):
			markers = append(markers, "DocuSign")
		}
	}
	if len(markers) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:             "dns-thirdparty-txt",
		Category:       "information_disclosure",
		Severity:       "info",
		Title:          "Third-party verification records in TXT",
		Detail:         strings.Join(markers, ", "),
		Recommendation: "Remove stale verification tokens after onboarding.",
		Evidence:       markers,
	}}
}

var (
	dynamicDNSHints = []string{
		"duckdns.org", "no-ip.com", "dynu.com", "freeddns.org", "changeip.com",
		"ddns.net", "hopto.org", "zapto.org", "3utilities.com", "bounceme.net",
	}
	parkingHints = []string{
		"parkingcrew.net", "sedoparking.com", "above.com", "parklogic.com",
		"namedrive.com", "bodis.com",
	}
	cdnWAFHints = []string{
		"cloudflare", "fastly", "akamai", "edgesuite.net", "cloudfront.net",
		"azurefd.net", "imperva", "incapsula", "stackpath", "edgio.net",
	}
)

func auditInfrastructureFingerprints(targets []string, raw map[string][]string) []model.Finding {
	var out []model.Finding
	joined := strings.ToLower(strings.Join(targets, " "))
	for _, h := range dynamicDNSHints {
		if strings.Contains(joined, h) {
			out = append(out, model.Finding{
				ID:             "dns-dynamic-provider",
				Category:       "threat_intelligence",
				Severity:       "medium",
				Title:          "Dynamic DNS provider pattern in DNS targets",
				Detail:         h,
				Recommendation: "Dynamic DNS is common in transient or malicious infrastructure; validate legitimacy.",
			})
			break
		}
	}
	for _, h := range parkingHints {
		if strings.Contains(joined, h) {
			out = append(out, model.Finding{
				ID:             "dns-parking",
				Category:       "information_disclosure",
				Severity:       "info",
				Title:          "Possible domain parking target",
				Detail:         h,
				Recommendation: "Remove parking if the domain is in active use.",
			})
			break
		}
	}
	for _, h := range cdnWAFHints {
		if strings.Contains(joined, h) {
			out = append(out, model.Finding{
				ID:             "dns-waf-cdn",
				Category:       "advanced_dns",
				Severity:       "info",
				Title:          "CDN/WAF/proxy pattern detected",
				Detail:         h,
				Recommendation: "Understand shared responsibility: TLS/DNS may terminate at the edge provider.",
			})
			break
		}
	}
	for _, t := range raw["TXT"] {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			low := strings.ToLower(t)
			for _, h := range dynamicDNSHints {
				if strings.Contains(low, h) {
					out = append(out, model.Finding{
						ID:             "dns-spf-dynamic-include",
						Category:       "email_auth",
						Severity:       "medium",
						Title:          "SPF references dynamic DNS pattern",
						Detail:         h,
						Recommendation: "Avoid dynamic DNS in SPF includes for primary domains.",
					})
					break
				}
			}
		}
	}
	return out
}

func auditDNSSEC(ctx context.Context, client *http.Client, zone string) []model.Finding {
	ds, err := dohResolve(ctx, client, zone, dns.TypeDS)
	if err != nil {
		return nil
	}
	answers, _ := ds["answers"].([]string)
	if len(answers) == 0 {
		return []model.Finding{{
			ID:             "dns-dnssec-unsigned",
			Category:       "dnssec",
			Severity:       "info",
			Title:          "DNSSEC signing not observed (no DS records)",
			Detail:         "No DS RRset returned for this name via Google Public DNS JSON API.",
			Recommendation: "Consider DNSSEC if you need cache poisoning resistance; publish DS at the parent.",
		}}
	}
	return nil
}

func auditApexLabels(zone string) []model.Finding {
	low := strings.ToLower(zone)
	keywords := []string{"ai", "ml", "gpt", "llm", "jupyter", "notebook", "staging", "dev", "test", "admin"}
	for _, k := range keywords {
		if strings.Contains(low, k) {
			return []model.Finding{{
				ID:             "dns-ai-surface-hint",
				Category:       "attack_surface",
				Severity:       "info",
				Title:          "Apex label hints at non-production or AI-related surface",
				Detail:         zone,
				Recommendation: "Ensure experimental systems are not exposed without controls.",
			}}
		}
	}
	return nil
}

func flattenCNAMEChain(ctx context.Context, c *dns.Client, zoneFQDN string, seeds []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, s := range seeds {
		cur := s
		for i := 0; i < 8 && cur != ""; i++ {
			if _, ok := seen[cur]; ok {
				break
			}
			seen[cur] = struct{}{}
			out = append(out, cur)
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(cur), dns.TypeCNAME)
			m.RecursionDesired = true
			r, _, err := c.ExchangeContext(ctx, m, publicResolver())
			if err != nil || r == nil {
				break
			}
			tmp := map[string][]string{}
			collectFromMsg(tmp, r)
			if len(tmp["CNAME"]) == 0 {
				break
			}
			cur = tmp["CNAME"][0]
		}
	}
	return out
}

func dohResolve(ctx context.Context, client *http.Client, name string, qtype uint16) (map[string]any, error) {
	if client == nil {
		client = http.DefaultClient
	}
	u := "https://dns.google/resolve?name=" + url.QueryEscape(name) + "&type=" + strconv.Itoa(int(qtype))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	var msg struct {
		Status int  `json:"Status"`
		AD     bool `json:"AD"`
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, err
	}
	var answers []string
	for _, a := range msg.Answer {
		if strings.TrimSpace(a.Data) != "" {
			answers = append(answers, strings.TrimSpace(a.Data))
		}
	}
	return map[string]any{
		"status":  msg.Status,
		"ad":      msg.AD,
		"answers": answers,
	}, nil
}

func sortFindings(f []model.Finding) {
	order := map[string]int{
		"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5,
	}
	sort.SliceStable(f, func(i, j int) bool {
		ai := order[strings.ToLower(f[i].Severity)]
		aj := order[strings.ToLower(f[j].Severity)]
		if ai != aj {
			return ai < aj
		}
		return f[i].ID < f[j].ID
	})
}
