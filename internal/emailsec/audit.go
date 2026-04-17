package emailsec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"recordscan/internal/model"
)

// Common DKIM selectors used by major providers (best-effort discovery).
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
	"mail", "smtp", "dkim", "mandrill", "cm", "pic", "hs1", "hs2",
	"protonmail", "pm", "resend", "zendesk1", "everlytic", "mxvault",
	"fm0", "smtpapi", "scph0823", "amazonses",
}

// Run performs deep email authentication and transport checks for the apex zone.
func Run(ctx context.Context, zone string, timeout time.Duration, httpClient *http.Client) model.EmailSecReport {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	zone = strings.Trim(strings.TrimSpace(strings.ToLower(zone)), ".")
	zfq := fqdn(zone)
	c := &dns.Client{Net: "udp", Timeout: timeout}

	rep := model.EmailSecReport{
		Metadata: model.ScanMetadata{
			ToolVersion:  model.Version,
			TargetHost:   zone,
			ScannedAtUTC: time.Now().UTC().Format(time.RFC3339),
			Elapsed:      "0s",
			OutDir:       "",
		},
		Zone:      zone,
		Technical: map[string]any{},
	}

	start := time.Now()
	defer func() {
		rep.Metadata.Elapsed = time.Since(start).String()
	}()

	mxLines := lookupMX(ctx, c, zfq)
	for _, line := range mxLines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pr, _ := strconv.Atoi(parts[0])
		host := strings.TrimSpace(parts[1])
		row := model.EmailMXRow{Priority: pr, Host: host}
		row.Resolved = lookupA(ctx, c, host)
		if len(row.Resolved) == 0 {
			row.Notes = "MX host has no A record from this resolver"
		}
		rep.MX = append(rep.MX, row)
	}
	sort.Slice(rep.MX, func(i, j int) bool {
		if rep.MX[i].Priority != rep.MX[j].Priority {
			return rep.MX[i].Priority < rep.MX[j].Priority
		}
		return rep.MX[i].Host < rep.MX[j].Host
	})

	apexTXT := lookupTXT(ctx, c, zfq)
	spfList := collectSPFRecords(apexTXT)

	var spfSec *model.EmailSPFSection
	if len(spfList) > 0 {
		primary := spfList[0]
		seen := map[string]struct{}{}
		nLook, detail := estimateSPFLookups(ctx, c, primary, 0, seen)
		hasPTR, redir := spfMechanismNotes(primary)
		spfSec = &model.EmailSPFSection{
			RawRecords:     append([]string(nil), spfList...),
			PrimaryRecord:  primary,
			LookupEstimate: nLook,
			LookupDetail:   strings.TrimSpace(detail),
			EndsWithAll:    spfTerminator(primary),
			HasPTR:         hasPTR,
			HasRedirect:    redir != "",
			RedirectTarget: redir,
		}
	}
	rep.SPF = spfSec

	dmarcRec := lookupTXT(ctx, c, "_dmarc."+zfq)
	var dmarcSec *model.EmailDMARCSection
	if len(dmarcRec) > 0 {
		tags := parseDMARCTags(dmarcRec)
		dmarcSec = &model.EmailDMARCSection{
			RawRecords: append([]string(nil), dmarcRec...),
			Tags:       tags,
			Policy:     tags["p"],
			Subpolicy:  tags["sp"],
			Pct:        tags["pct"],
			RUA:        tags["rua"],
			RUF:        tags["ruf"],
			ADKIM:      tags["adkim"],
			ASPF:       tags["aspf"],
		}
	}
	rep.DMARC = dmarcSec

	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + zfq
		txts := lookupTXT(ctx, c, name)
		if len(txts) == 0 {
			rep.DKIM = append(rep.DKIM, model.EmailDKIMRow{Selector: sel, Found: false})
			continue
		}
		valid := false
		for _, t := range txts {
			low := strings.ToLower(t)
			if strings.Contains(low, "v=dkim1") {
				valid = true
				break
			}
		}
		if !valid {
			for _, t := range txts {
				low := strings.ToLower(t)
				if strings.Contains(low, "k=") && strings.Contains(low, "p=") {
					valid = true
					break
				}
			}
		}
		row := model.EmailDKIMRow{Selector: sel, Found: valid, Records: txts}
		if len(txts) > 0 && !valid {
			row.Notes = "TXT present but not a typical DKIM record"
		}
		rep.DKIM = append(rep.DKIM, row)
	}

	mtaTXT := lookupTXT(ctx, c, "_mta-sts."+zfq)
	var mta model.EmailMTASTSBlock
	if len(mtaTXT) > 0 {
		mta.TXTRecord = strings.Join(mtaTXT, " | ")
		for _, t := range mtaTXT {
			low := strings.ToLower(t)
			if !strings.Contains(low, "v=stsv1") {
				continue
			}
			parts := strings.Split(t, ";")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(strings.ToLower(p), "id=") {
					mta.ID = strings.TrimSpace(p[3:])
				}
			}
		}
		policyURL := "https://mta-sts." + zone + "/.well-known/mta-sts.txt"
		mta.PolicyURL = policyURL
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
		if err == nil {
			resp, err := httpClient.Do(req)
			if err != nil {
				mta.PolicyFetch = err.Error()
			} else {
				func() {
					defer resp.Body.Close()
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
					if resp.StatusCode != http.StatusOK {
						mta.PolicyFetch = fmt.Sprintf("HTTP %d", resp.StatusCode)
						return
					}
					body := string(b)
					mta.PolicyBody = body
					for _, line := range strings.Split(body, "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(strings.ToLower(line), "version:") {
							continue
						}
						low := strings.ToLower(line)
						if strings.HasPrefix(low, "mode:") {
							mta.Mode = strings.TrimSpace(line[5:])
						}
						if strings.HasPrefix(low, "max_age:") {
							mta.MaxAge = strings.TrimSpace(line[8:])
						}
						if strings.HasPrefix(low, "mx:") {
							if mta.MXPatterns != "" {
								mta.MXPatterns += ", "
							}
							mta.MXPatterns += strings.TrimSpace(line[3:])
						}
					}
				}()
			}
		}
	}
	if mta.TXTRecord != "" || mta.PolicyURL != "" {
		rep.MTASTS = &mta
	}

	tlsrpt := lookupTXT(ctx, c, "_smtp._tls."+zfq)
	if len(tlsrpt) > 0 {
		joined := strings.Join(tlsrpt, " | ")
		b := model.EmailTLSRPTBlock{TXTRecord: joined}
		low := strings.ToLower(joined)
		if i := strings.Index(low, "rua="); i >= 0 {
			rest := joined[i+4:]
			if idx := strings.IndexAny(rest, " ;"); idx >= 0 {
				b.RUA = strings.TrimSpace(rest[:idx])
			} else {
				b.RUA = strings.TrimSpace(rest)
			}
		}
		rep.TLSRPT = &b
	}

	bimi := lookupTXT(ctx, c, "default._bimi."+zfq)
	if len(bimi) > 0 {
		rep.BIMI = &model.EmailBIMIBlock{
			TXTRecord: strings.Join(bimi, " | "),
		}
		if !strings.Contains(strings.ToLower(rep.BIMI.TXTRecord), "v=bimi1") {
			rep.BIMI.Notes = "TXT at default._bimi may not be a BIMI record"
		}
	}

	var findings []model.Finding
	findings = append(findings, auditSPFFindings(zone, spfSec, spfList)...)
	if len(rep.MX) == 0 {
		findings = append(findings, model.Finding{
			ID:             "email-mx-missing",
			Category:       "email_transport",
			Severity:       "high",
			Title:          "No MX records",
			Detail:         "This apex has no MX; inbound SMTP may be undefined or use A/AAAA fallback only.",
			Recommendation: "Publish MX records pointing at your inbound mail gateways.",
		})
	} else if len(rep.MX) == 1 {
		findings = append(findings, model.Finding{
			ID:             "email-mx-single",
			Category:       "email_transport",
			Severity:       "low",
			Title:          "Only one MX host",
			Detail:         "A single MX reduces failover options.",
			Recommendation: "Add secondary MX or ensure provider SLA covers outages.",
		})
	}

	if dmarcSec != nil {
		findings = append(findings, auditDMARCFindings(zone, dmarcSec.RawRecords, dmarcSec.Tags)...)
	} else {
		findings = append(findings, auditDMARCFindings(zone, nil, nil)...)
	}

	dkimFound := 0
	for _, d := range rep.DKIM {
		if d.Found && d.Notes == "" {
			dkimFound++
			findings = append(findings, auditDKIMKey(d.Records)...)
		}
	}
	if dkimFound == 0 {
		findings = append(findings, model.Finding{
			ID:             "email-dkim-none-probed",
			Category:       "email_auth",
			Severity:       "medium",
			Title:          "No DKIM DNS for common selectors",
			Detail:         fmt.Sprintf("Probed %d common selectors under %s._domainkey; none matched a DKIM record.", len(dkimSelectors), zone),
			Recommendation: "Publish DKIM TXT for each active signing selector your MTA uses (see vendor docs).",
		})
	}

	if rep.MTASTS == nil {
		findings = append(findings, model.Finding{
			ID:             "email-mta-sts-missing",
			Category:       "email_transport",
			Severity:       "medium",
			Title:          "MTA-STS not configured",
			Detail:         "No _mta-sts TXT or policy fetch attempted.",
			Recommendation: "Deploy MTA-STS (DNS TXT + HTTPS policy) to encourage encrypted SMTP between MTAs.",
		})
	} else if rep.MTASTS.PolicyFetch != "" {
		findings = append(findings, model.Finding{
			ID:             "email-mta-sts-policy-fetch",
			Category:       "email_transport",
			Severity:       "medium",
			Title:          "MTA-STS policy could not be retrieved",
			Detail:         rep.MTASTS.PolicyFetch,
			Recommendation: "Ensure https://mta-sts." + zone + "/.well-known/mta-sts.txt returns 200 with a valid policy.",
		})
	} else if strings.EqualFold(strings.TrimSpace(rep.MTASTS.Mode), "testing") {
		findings = append(findings, model.Finding{
			ID:             "email-mta-sts-testing",
			Category:       "email_transport",
			Severity:       "low",
			Title:          "MTA-STS mode is testing",
			Detail:         "Peers may not enforce TLS while policy is in testing.",
			Recommendation: "Switch to mode: enforce after validation.",
		})
	}

	if rep.TLSRPT == nil {
		findings = append(findings, model.Finding{
			ID:             "email-tls-rpt-missing",
			Category:       "email_transport",
			Severity:       "low",
			Title:          "TLS reporting (SMTP TLS) TXT not found",
			Detail:         fmt.Sprintf("No _smtp._tls.%s record.", zone),
			Recommendation: "Publish TLSRPT v=TLSRPTv1 with rua= for visibility into SMTP TLS failures.",
		})
	}

	sortEmailFindings(findings)
	rep.Findings = findings

	rep.Controls = buildControls(&rep)
	rep.Summary = summarizeEmail(&rep)

	return rep
}

func buildControls(rep *model.EmailSecReport) []model.EmailControl {
	var cc []model.EmailControl
	add := func(id, area, title, status, detail string) {
		cc = append(cc, model.EmailControl{ID: id, Area: area, Title: title, Status: status, Detail: detail})
	}

	if len(rep.MX) > 0 {
		add("mx-present", "Inbound routing", "MX records published", "pass", fmt.Sprintf("%d MX host(s) configured.", len(rep.MX)))
	} else {
		add("mx-present", "Inbound routing", "MX records published", "fail", "No MX records at apex.")
	}

	if rep.SPF != nil && len(rep.SPF.RawRecords) == 1 {
		term := rep.SPF.EndsWithAll
		switch term {
		case "-all":
			add("spf-hardfail", "Sender policy (SPF)", "SPF default is hard fail (-all)", "pass", "Strongest SPF stance for unauthorized senders.")
		case "~all":
			add("spf-softfail", "Sender policy (SPF)", "SPF default is soft fail (~all)", "warn", "Receivers may still accept spoofed mail; consider -all when safe.")
		case "+all":
			add("spf-plusall", "Sender policy (SPF)", "SPF policy", "fail", "SPF allows any sender (+all).")
		case "":
			add("spf-term", "Sender policy (SPF)", "SPF all mechanism", "warn", "SPF should end with -all or ~all.")
		default:
			add("spf-term", "Sender policy (SPF)", "SPF all mechanism", "warn", "Review SPF terminator: "+term)
		}
		if rep.SPF.LookupEstimate > 10 {
			add("spf-lookups", "Sender policy (SPF)", "SPF DNS lookup budget", "fail", fmt.Sprintf("Estimated %d lookups (limit 10).", rep.SPF.LookupEstimate))
		} else if rep.SPF.LookupEstimate > 7 {
			add("spf-lookups", "Sender policy (SPF)", "SPF DNS lookup budget", "warn", fmt.Sprintf("Estimated %d lookups; keep headroom under the 10 lookup cap.", rep.SPF.LookupEstimate))
		} else {
			add("spf-lookups", "Sender policy (SPF)", "SPF DNS lookup budget", "pass", fmt.Sprintf("Estimated %d DNS lookups (under RFC 7208 limits).", rep.SPF.LookupEstimate))
		}
	} else if rep.SPF != nil && len(rep.SPF.RawRecords) > 1 {
		add("spf-single", "Sender policy (SPF)", "Single SPF TXT record", "fail", "Multiple SPF records invalidate SPF.")
	} else {
		add("spf-exists", "Sender policy (SPF)", "SPF record present", "fail", "No SPF TXT at apex.")
	}

	if rep.DMARC != nil && strings.Contains(strings.ToLower(strings.Join(rep.DMARC.RawRecords, " ")), "v=dmarc1") {
		p := strings.ToLower(rep.DMARC.Policy)
		switch p {
		case "reject":
			add("dmarc-p", "Domain DMARC", "DMARC organizational policy", "pass", "p=reject protects the domain from unauthenticated use in many receivers.")
		case "quarantine":
			add("dmarc-p", "Domain DMARC", "DMARC organizational policy", "warn", "p=quarantine is strong; consider reject after monitoring.")
		case "none":
			add("dmarc-p", "Domain DMARC", "DMARC organizational policy", "warn", "p=none is monitoring only; plan to tighten.")
		default:
			add("dmarc-p", "Domain DMARC", "DMARC organizational policy", "warn", "Policy p="+rep.DMARC.Policy)
		}
		if rep.DMARC.RUA != "" {
			add("dmarc-rua", "Domain DMARC", "Aggregate reporting (rua)", "pass", trimDetail(rep.DMARC.RUA, 120))
		} else {
			add("dmarc-rua", "Domain DMARC", "Aggregate reporting (rua)", "fail", "No rua= configured.")
		}
	} else {
		add("dmarc-exists", "Domain DMARC", "DMARC DNS record", "fail", "No DMARC at _dmarc."+rep.Zone+".")
	}

	dkimN := 0
	for _, d := range rep.DKIM {
		if d.Found && d.Notes == "" {
			dkimN++
		}
	}
	if dkimN > 0 {
		add("dkim-dns", "DKIM", "DKIM DNS for probed selectors", "pass", fmt.Sprintf("%d selector(s) publish DKIM keys.", dkimN))
	} else {
		add("dkim-dns", "DKIM", "DKIM DNS for probed selectors", "fail", "No DKIM keys found for common selectors.")
	}

	if rep.MTASTS != nil && rep.MTASTS.PolicyFetch == "" && rep.MTASTS.PolicyBody != "" {
		add("mta-sts", "Transport (MTA-STS)", "MTA-STS policy available", "pass", "HTTPS policy file retrieved.")
	} else if rep.MTASTS != nil {
		add("mta-sts", "Transport (MTA-STS)", "MTA-STS policy available", "warn", "STS TXT or policy file needs attention.")
	} else {
		add("mta-sts", "Transport (MTA-STS)", "MTA-STS", "fail", "Not configured.")
	}

	if rep.TLSRPT != nil {
		add("tlsrpt", "Transport (TLS-RPT)", "SMTP TLS reporting", "pass", "TLSRPT record present.")
	} else {
		add("tlsrpt", "Transport (TLS-RPT)", "SMTP TLS reporting", "warn", "No _smtp._tls record.")
	}

	if rep.BIMI != nil {
		add("bimi", "Brand (BIMI)", "BIMI indicator record", "pass", "default._bimi TXT present.")
	} else {
		add("bimi", "Brand (BIMI)", "BIMI indicator record", "warn", "Optional: no default._bimi record.")
	}

	return cc
}

func trimDetail(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func summarizeEmail(rep *model.EmailSecReport) model.EmailSecSummary {
	s := model.EmailSecSummary{
		BySeverity: map[string]int{},
	}
	pass, warn, fail := 0, 0, 0
	for _, c := range rep.Controls {
		switch strings.ToLower(c.Status) {
		case "pass":
			pass++
		case "warn":
			warn++
		case "fail":
			fail++
		}
	}
	s.ControlsPass = pass
	s.ControlsWarn = warn
	s.ControlsFail = fail
	s.MXCount = len(rep.MX)
	for _, d := range rep.DKIM {
		if d.Found && d.Notes == "" {
			s.DKIMPublishers++
		}
	}
	s.HasSPF = rep.SPF != nil && len(rep.SPF.RawRecords) > 0
	s.HasDMARC = rep.DMARC != nil && len(rep.DMARC.RawRecords) > 0
	s.MTASTSEnabled = rep.MTASTS != nil && rep.MTASTS.PolicyFetch == "" && rep.MTASTS.PolicyBody != ""
	s.TLSRPTPublished = rep.TLSRPT != nil

	for _, f := range rep.Findings {
		k := strings.ToLower(f.Severity)
		if k == "" {
			k = "unknown"
		}
		s.BySeverity[k]++
		s.FindingsTotal++
	}

	totalC := pass + warn + fail
	if totalC == 0 {
		s.PostureScore = 0
		s.PostureLabel = "Unknown"
		return s
	}
	// Weighted score: pass=100, warn=60, fail=0 per control
	score := (pass*100 + warn*60 + fail*0) / totalC
	s.PostureScore = score
	switch {
	case score >= 85:
		s.PostureLabel = "Strong"
	case score >= 65:
		s.PostureLabel = "Moderate"
	case score >= 40:
		s.PostureLabel = "Weak"
	default:
		s.PostureLabel = "Critical risk"
	}
	return s
}
