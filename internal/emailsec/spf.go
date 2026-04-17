package emailsec

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"

	"recordscan/internal/model"
)

var spfTokenSplit = regexp.MustCompile(`\s+`)

func collectSPFRecords(apexTXT []string) []string {
	var spf []string
	for _, t := range apexTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = append(spf, t)
		}
	}
	return spf
}

// estimateSPFLookups walks include: chains (depth-limited) to approximate RFC 7208 DNS lookup cost.
func estimateSPFLookups(ctx context.Context, c *dns.Client, spf string, depth int, seen map[string]struct{}) (int, string) {
	if depth > 5 || spf == "" {
		return 0, ""
	}
	tokens := spfTokenSplit.Split(strings.TrimSpace(spf), -1)
	var detail strings.Builder
	total := 0
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lt := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lt, "include:"):
			domain := strings.TrimSpace(tok[len("include:"):])
			if domain == "" {
				continue
			}
			if _, ok := seen[domain]; ok {
				detail.WriteString(fmt.Sprintf("include:%s (loop skipped); ", domain))
				continue
			}
			seen[domain] = struct{}{}
			total++
			txts := lookupTXT(ctx, c, domain)
			var sub string
			for _, x := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(x)), "v=spf1") {
					sub = x
					break
				}
			}
			if sub != "" {
				n, d := estimateSPFLookups(ctx, c, sub, depth+1, seen)
				total += n
				if d != "" {
					detail.WriteString(d)
				}
			} else {
				detail.WriteString(fmt.Sprintf("include:%s (no SPF at target); ", domain))
			}
			delete(seen, domain)
		case strings.HasPrefix(lt, "redirect="):
			target := strings.TrimSpace(tok[len("redirect="):])
			if target == "" {
				continue
			}
			if _, ok := seen[target]; ok {
				break
			}
			seen[target] = struct{}{}
			total++
			txts := lookupTXT(ctx, c, target)
			var sub string
			for _, x := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(x)), "v=spf1") {
					sub = x
					break
				}
			}
			if sub != "" {
				n, d := estimateSPFLookups(ctx, c, sub, depth+1, seen)
				total += n
				if d != "" {
					detail.WriteString(d)
				}
			}
			delete(seen, target)
		default:
			if spfMechanismLookupCost(lt) {
				total++
			}
		}
	}
	return total, detail.String()
}

func spfMechanismLookupCost(lt string) bool {
	switch {
	case lt == "a", lt == "mx", lt == "ptr":
		return true
	case strings.HasPrefix(lt, "a:"), strings.HasPrefix(lt, "a/"):
		return true
	case strings.HasPrefix(lt, "mx:"), strings.HasPrefix(lt, "mx/"):
		return true
	case strings.HasPrefix(lt, "exists:"):
		return true
	case strings.HasPrefix(lt, "ptr:"):
		return true
	default:
		return false
	}
}

func spfTerminator(spf string) string {
	low := strings.TrimSpace(strings.ToLower(spf))
	switch {
	case strings.Contains(low, "+all"):
		return "+all"
	case strings.HasSuffix(low, "-all"):
		return "-all"
	case strings.HasSuffix(low, "~all"):
		return "~all"
	case strings.HasSuffix(low, "?all"):
		return "?all"
	default:
		return ""
	}
}

func spfMechanismNotes(spf string) (hasPTR bool, redirect string) {
	low := strings.ToLower(spf)
	hasPTR = strings.Contains(low, " ptr") || strings.Contains(low, "ptr:") || strings.HasPrefix(strings.TrimSpace(low), "v=spf1 ptr")
	for _, tok := range spfTokenSplit.Split(strings.TrimSpace(spf), -1) {
		t := strings.ToLower(strings.TrimSpace(tok))
		if strings.HasPrefix(t, "redirect=") {
			redirect = strings.TrimSpace(tok[len("redirect="):])
		} else if strings.HasPrefix(t, "redirect:") {
			redirect = strings.TrimSpace(tok[len("redirect:"):])
		}
	}
	return hasPTR, redirect
}

func auditSPFFindings(zone string, section *model.EmailSPFSection, spfList []string) []model.Finding {
	var out []model.Finding
	if len(spfList) == 0 {
		out = append(out, model.Finding{
			ID:             "email-spf-missing",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "No SPF record at zone apex",
			Detail:         fmt.Sprintf("No TXT record starting with v=spf1 was found for %s.", zone),
			Recommendation: "Publish a single SPF record listing authorized senders; end with -all or ~all.",
		})
		return out
	}
	if len(spfList) > 1 {
		out = append(out, model.Finding{
			ID:             "email-spf-multiple",
			Category:       "email_auth",
			Severity:       "critical",
			Title:          "Multiple SPF records at apex (invalid)",
			Detail:         fmt.Sprintf("%d distinct SPF TXT records; SPF must be a single TXT RRSet.", len(spfList)),
			Recommendation: "Merge into one SPF record or remove duplicates; multiple SPF records cause permanent SPF failure.",
		})
	}
	primary := spfList[0]
	low := strings.ToLower(primary)
	if strings.Contains(low, "+all") {
		out = append(out, model.Finding{
			ID:             "email-spf-plus-all",
			Category:       "email_auth",
			Severity:       "critical",
			Title:          "SPF allows any sender (+all)",
			Detail:         primary,
			Recommendation: "Remove +all and enumerate legitimate mail sources.",
		})
	}
	if strings.HasSuffix(strings.TrimSpace(low), "?all") {
		out = append(out, model.Finding{
			ID:             "email-spf-neutral-all",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "SPF ends with ?all (neutral)",
			Detail:         primary,
			Recommendation: "Use -all or ~all for a clear policy stance.",
		})
	}
	if !strings.Contains(low, "-all") && !strings.Contains(low, "~all") {
		out = append(out, model.Finding{
			ID:             "email-spf-no-fail",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "SPF lacks -all or ~all default",
			Detail:         primary,
			Recommendation: "Terminate SPF with -all (hard fail) or ~all (soft fail).",
		})
	}
	if section != nil && section.HasPTR {
		out = append(out, model.Finding{
			ID:             "email-spf-ptr",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "SPF uses ptr mechanism (deprecated / slow)",
			Detail:         "The ptr mechanism is slow, unreliable, and discouraged by RFC 7208.",
			Recommendation: "Replace ptr with explicit ip4/ip6/include mechanisms.",
		})
	}
	if section != nil && section.LookupEstimate > 10 {
		out = append(out, model.Finding{
			ID:             "email-spf-lookup-limit",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "SPF may exceed DNS lookup limits",
			Detail:         fmt.Sprintf("Estimated %d chained lookups (RFC7208 limit is 10).", section.LookupEstimate),
			Recommendation: "Flatten includes, remove unused mechanisms, or split mail streams across subdomains.",
		})
	}
	return out
}

func parseDMARCTags(records []string) map[string]string {
	tags := map[string]string{}
	for _, r := range records {
		parts := strings.Split(r, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.TrimSpace(strings.ToLower(kv[0]))
			tags[k] = strings.TrimSpace(kv[1])
		}
	}
	return tags
}

func auditDMARCFindings(zone string, records []string, tags map[string]string) []model.Finding {
	if tags == nil {
		tags = map[string]string{}
	}
	var out []model.Finding
	if len(records) == 0 {
		out = append(out, model.Finding{
			ID:             "email-dmarc-missing",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "No DMARC record",
			Detail:         fmt.Sprintf("No DMARC TXT at _dmarc.%s.", zone),
			Recommendation: "Publish v=DMARC1 with p=none|quarantine|reject and rua= aggregate reporting.",
		})
		return out
	}
	joined := strings.ToLower(strings.Join(records, " "))
	if !strings.Contains(joined, "v=dmarc1") {
		out = append(out, model.Finding{
			ID:             "email-dmarc-malformed",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "DMARC record may be malformed",
			Detail:         strings.Join(records, " | "),
			Recommendation: "Start the record with v=DMARC1;",
		})
	}
	p := strings.ToLower(tags["p"])
	switch p {
	case "":
		out = append(out, model.Finding{
			ID:             "email-dmarc-no-p",
			Category:       "email_auth",
			Severity:       "high",
			Title:          "DMARC missing p= policy",
			Detail:         strings.Join(records, " | "),
			Recommendation: "Set p=none during monitoring, then quarantine or reject.",
		})
	case "none":
		out = append(out, model.Finding{
			ID:             "email-dmarc-monitor",
			Category:       "email_auth",
			Severity:       "low",
			Title:          "DMARC policy is p=none (monitoring only)",
			Detail:         strings.Join(records, " | "),
			Recommendation: "Move to p=quarantine then p=reject after reviewing aggregate reports.",
		})
	}
	if tags["rua"] == "" {
		out = append(out, model.Finding{
			ID:             "email-dmarc-no-rua",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "DMARC has no rua= aggregate reporting address",
			Detail:         "Without rua, you will not receive DMARC aggregate reports.",
			Recommendation: "Add rua=mailto:dmarc@yourdomain (and verify the mailbox).",
		})
	}
	if adkim := strings.ToLower(tags["adkim"]); adkim == "s" {
		out = append(out, model.Finding{
			ID:             "email-dmarc-strict-dkim",
			Category:       "email_auth",
			Severity:       "info",
			Title:          "DMARC DKIM alignment is strict (adkim=s)",
			Detail:         "Strict alignment can cause legitimate mail to fail if DKIM d= does not match From domain.",
			Recommendation: "Confirm all sending systems sign with aligned DKIM domains.",
		})
	}
	return out
}

func auditDKIMKey(records []string) []model.Finding {
	var out []model.Finding
	re := regexp.MustCompile(`p=([A-Za-z0-9+/=]+)`)
	for _, r := range records {
		if !strings.Contains(strings.ToLower(r), "v=dkim1") && !strings.Contains(strings.ToLower(r), "k=") {
			continue
		}
		m := re.FindStringSubmatch(r)
		if len(m) != 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			out = append(out, model.Finding{
				ID:             "email-dkim-decode",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "DKIM public key may be malformed",
				Detail:         err.Error(),
				Recommendation: "Fix p= base64 in DKIM DNS record.",
			})
			continue
		}
		if bits := len(raw) * 8; bits > 0 && bits < 2048 && strings.Contains(strings.ToLower(r), "k=rsa") {
			out = append(out, model.Finding{
				ID:             "email-dkim-weak-rsa",
				Category:       "email_auth",
				Severity:       "medium",
				Title:          "DKIM RSA key appears under 2048-bit",
				Detail:         fmt.Sprintf("Decoded modulus ~%d bits", bits),
				Recommendation: "Rotate to RSA2048+ or ed25519.",
			})
		}
	}
	return out
}

func sortEmailFindings(ff []model.Finding) {
	order := map[string]int{
		"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5,
	}
	for i := 0; i < len(ff); i++ {
		for j := i + 1; j < len(ff); j++ {
			oi := order[strings.ToLower(ff[i].Severity)]
			oj := order[strings.ToLower(ff[j].Severity)]
			if oj < oi || (oj == oi && ff[j].ID < ff[i].ID) {
				ff[i], ff[j] = ff[j], ff[i]
			}
		}
	}
}
