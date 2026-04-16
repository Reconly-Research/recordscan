package httpaudit

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"recordscan/internal/model"
)

// Run fetches baseURL and logoutURL (optional) and evaluates security headers per the reference suite.
func Run(ctx context.Context, baseURL, logoutPath string, timeout time.Duration) model.HTTPReport {
	rep := model.HTTPReport{
		BaseURL: baseURL,
		Headers: make(model.HTTPHeaderKV),
		Tests:   nil,
	}
	if strings.TrimSpace(logoutPath) != "" {
		rep.LogoutURL = strings.Trim(strings.TrimSpace(logoutPath), "/")
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	req.Header.Set("User-Agent", "recordscan/"+model.Version)

	resp, err := client.Do(req)
	if err != nil {
		rep.Error = err.Error()
		rep.Findings = append(rep.Findings, model.Finding{
			ID:             "http-fetch-failed",
			Category:       "http",
			Severity:       "high",
			Title:          "HTTP request failed",
			Detail:         err.Error(),
			Recommendation: "Ensure the site is reachable over HTTP(S) from this network.",
		})
		return rep
	}
	defer resp.Body.Close()
	rep.StatusCode = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		rep.FinalURL = resp.Request.URL.String()
	}

	for k, v := range resp.Header {
		if len(v) == 0 {
			continue
		}
		ck := http.CanonicalHeaderKey(k)
		rep.Headers[ck] = strings.Join(v, ", ")
	}

	// Reference suite expects 200 for most checks.
	if resp.StatusCode != http.StatusOK {
		rep.Findings = append(rep.Findings, model.Finding{
			ID:             "http-non-200",
			Category:       "http",
			Severity:       "medium",
			Title:          fmt.Sprintf("Primary URL returned status %d", resp.StatusCode),
			Detail:         "Strict test suite expects 200 OK.",
			Recommendation: "Point recordscan at a URL that returns 200 for GET / or adjust expectations.",
		})
	}

	rep.Tests = append(rep.Tests, evalHSTS(rep.Headers, resp.StatusCode)...)
	rep.Tests = append(rep.Tests, evalXFO(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalXContentType(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalCSP(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalXPCDP(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalReferrer(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalCOEP(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalCOOP(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalCORP(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalPermissionsPolicy(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalCacheControl(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalDNSPrefetch(rep.Headers, resp.StatusCode))
	rep.Tests = append(rep.Tests, evalAbsentHeaders(rep.Headers, resp.StatusCode)...)
	rep.Tests = append(rep.Tests, evalClearSiteData(ctx, client, baseURL, rep.LogoutURL)...)

	for _, t := range rep.Tests {
		if t.Skipped {
			continue
		}
		if !t.Passed {
			sev := t.Severity
			if sev == "" {
				sev = "medium"
			}
			rep.Findings = append(rep.Findings, model.Finding{
				ID:             "http-test-" + strings.ReplaceAll(strings.ToLower(t.Name), " ", "-"),
				Category:       "http_headers",
				Severity:       sev,
				Title:          "HTTP header check failed: " + t.Name,
				Detail:         t.Detail,
				Recommendation: remediationFor(t.Name),
			})
		}
	}

	return rep
}

func remediationFor(name string) string {
	switch name {
	case "Strict-Transport-Security":
		return "Set Strict-Transport-Security with long max-age, includeSubDomains, and preload if appropriate."
	case "Content-Security-Policy":
		return "Deploy a strict CSP without unsafe-inline/unsafe-eval unless strictly required."
	case "Permissions-Policy":
		return "Send Permissions-Policy to disable sensitive features by default."
	default:
		return "Review OWASP Secure Headers guidance and align with your application needs."
	}
}

func statusOK(code int) bool { return code == http.StatusOK }

func evalHSTS(h model.HTTPHeaderKV, code int) []model.HTTPTest {
	if !statusOK(code) {
		return []model.HTTPTest{{Name: "Strict-Transport-Security", Passed: false, Detail: "status not 200"}}
	}
	v := h["Strict-Transport-Security"]
	if v == "" {
		return []model.HTTPTest{{Name: "Strict-Transport-Security", Passed: false, Detail: "header missing"}}
	}
	vlow := strings.ToLower(v)
	ok := strings.Contains(vlow, "max-age=63072000") && strings.Contains(vlow, "includesubdomains")
	if !ok {
		return []model.HTTPTest{{
			Name: "Strict-Transport-Security", Passed: false,
			Detail: "expected max-age=63072000 and includeSubDomains (optional preload)",
		}}
	}
	return []model.HTTPTest{{Name: "Strict-Transport-Security", Passed: true}}
}

func evalXFO(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "X-Frame-Options", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["X-Frame-Options"])
	if v == "" {
		return model.HTTPTest{Name: "X-Frame-Options", Passed: false, Detail: "header missing"}
	}
	if !strings.EqualFold(v, "deny") {
		return model.HTTPTest{Name: "X-Frame-Options", Passed: false, Detail: "strict suite expects DENY (got " + v + ")"}
	}
	return model.HTTPTest{Name: "X-Frame-Options", Passed: true}
}

func evalXContentType(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "X-Content-Type-Options", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["X-Content-Type-Options"])
	if strings.ToLower(v) != "nosniff" {
		return model.HTTPTest{Name: "X-Content-Type-Options", Passed: false, Detail: "expected nosniff"}
	}
	return model.HTTPTest{Name: "X-Content-Type-Options", Passed: true}
}

func evalCSP(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Content-Security-Policy", Passed: false, Detail: "status not 200"}
	}
	v := h["Content-Security-Policy"]
	if v == "" {
		return model.HTTPTest{Name: "Content-Security-Policy", Passed: false, Detail: "header missing"}
	}
	if strings.Contains(strings.ToLower(v), "unsafe") {
		return model.HTTPTest{Name: "Content-Security-Policy", Passed: false, Detail: "contains unsafe directive"}
	}
	return model.HTTPTest{Name: "Content-Security-Policy", Passed: true}
}

func evalXPCDP(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "X-Permitted-Cross-Domain-Policies", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["X-Permitted-Cross-Domain-Policies"])
	if strings.ToLower(v) != "none" {
		return model.HTTPTest{Name: "X-Permitted-Cross-Domain-Policies", Passed: false, Detail: "expected none"}
	}
	return model.HTTPTest{Name: "X-Permitted-Cross-Domain-Policies", Passed: true}
}

func evalReferrer(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Referrer-Policy", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["Referrer-Policy"])
	if strings.ToLower(v) != "no-referrer" {
		return model.HTTPTest{Name: "Referrer-Policy", Passed: false, Detail: "expected no-referrer"}
	}
	return model.HTTPTest{Name: "Referrer-Policy", Passed: true}
}

func evalCOEP(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Cross-Origin-Embedder-Policy", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["Cross-Origin-Embedder-Policy"])
	if strings.ToLower(v) != "require-corp" {
		return model.HTTPTest{Name: "Cross-Origin-Embedder-Policy", Passed: false, Detail: "expected require-corp"}
	}
	return model.HTTPTest{Name: "Cross-Origin-Embedder-Policy", Passed: true}
}

func evalCOOP(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Cross-Origin-Opener-Policy", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["Cross-Origin-Opener-Policy"])
	if strings.ToLower(v) != "same-origin" {
		return model.HTTPTest{Name: "Cross-Origin-Opener-Policy", Passed: false, Detail: "expected same-origin"}
	}
	return model.HTTPTest{Name: "Cross-Origin-Opener-Policy", Passed: true}
}

func evalCORP(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Cross-Origin-Resource-Policy", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["Cross-Origin-Resource-Policy"])
	if strings.ToLower(v) != "same-origin" {
		return model.HTTPTest{Name: "Cross-Origin-Resource-Policy", Passed: false, Detail: "expected same-origin"}
	}
	return model.HTTPTest{Name: "Cross-Origin-Resource-Policy", Passed: true}
}

var permissionsFragments = []string{
	"accelerometer=()", "autoplay=()", "camera=()", "clipboard-read=()", "clipboard-write=()",
	"cross-origin-isolated=()", "display-capture=()", "encrypted-media=()", "fullscreen=()",
	"gamepad=()", "geolocation=()", "gyroscope=()", "hid=()", "idle-detection=()",
	"interest-cohort=()", "keyboard-map=()", "magnetometer=()", "microphone=()", "midi=()",
	"payment=()", "picture-in-picture=()", "publickey-credentials-get=()", "screen-wake-lock=()",
	"serial=()", "unload=()", "usb=()", "web-share=()", "xr-spatial-tracking=()",
}

func evalPermissionsPolicy(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Permissions-Policy", Passed: false, Detail: "status not 200"}
	}
	v := h["Permissions-Policy"]
	if v == "" {
		v = h["Feature-Policy"]
	}
	if v == "" {
		return model.HTTPTest{Name: "Permissions-Policy", Passed: false, Detail: "header missing"}
	}
	low := strings.ToLower(v)
	for _, frag := range permissionsFragments {
		if !strings.Contains(low, strings.ToLower(frag)) {
			return model.HTTPTest{Name: "Permissions-Policy", Passed: false, Detail: "missing " + frag}
		}
	}
	if !strings.Contains(low, "sync-xhr=(self)") && !strings.Contains(low, "sync-xhr=()") {
		return model.HTTPTest{Name: "Permissions-Policy", Passed: false, Detail: "missing sync-xhr restriction"}
	}
	return model.HTTPTest{Name: "Permissions-Policy", Passed: true}
}

func evalCacheControl(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "Cache-Control", Passed: false, Detail: "status not 200"}
	}
	v := strings.TrimSpace(h["Cache-Control"])
	if strings.ToLower(v) != "no-store, max-age=0" {
		// allow equivalent comma ordering
		parts := strings.Split(strings.ToLower(v), ",")
		hasNoStore, hasMax0 := false, false
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "no-store" {
				hasNoStore = true
			}
			if p == "max-age=0" {
				hasMax0 = true
			}
		}
		if !(hasNoStore && hasMax0) {
			return model.HTTPTest{Name: "Cache-Control", Passed: false, Detail: "expected no-store, max-age=0"}
		}
	}
	return model.HTTPTest{Name: "Cache-Control", Passed: true}
}

func evalDNSPrefetch(h model.HTTPHeaderKV, code int) model.HTTPTest {
	if !statusOK(code) {
		return model.HTTPTest{Name: "X-DNS-Prefetch-Control", Passed: false, Detail: "status not 200"}
	}
	v := h["X-DNS-Prefetch-Control"]
	if v == "" {
		v = h["X-Dns-Prefetch-Control"]
	}
	if strings.ToLower(strings.TrimSpace(v)) != "off" {
		return model.HTTPTest{Name: "X-DNS-Prefetch-Control", Passed: false, Detail: "expected off"}
	}
	return model.HTTPTest{Name: "X-DNS-Prefetch-Control", Passed: true}
}

func evalAbsentHeaders(h model.HTTPHeaderKV, code int) []model.HTTPTest {
	if !statusOK(code) {
		return nil
	}
	var t []model.HTTPTest
	if h["Feature-Policy"] != "" {
		t = append(t, model.HTTPTest{Name: "Feature-Policy (should not exist)", Passed: false, Detail: "deprecated header present"})
	} else {
		t = append(t, model.HTTPTest{Name: "Feature-Policy (should not exist)", Passed: true})
	}
	if h["Public-Key-Pins"] != "" {
		t = append(t, model.HTTPTest{Name: "Public-Key-Pins (should not exist)", Passed: false, Detail: "HPKP present"})
	} else {
		t = append(t, model.HTTPTest{Name: "Public-Key-Pins (should not exist)", Passed: true})
	}
	if h["Expect-CT"] != "" {
		t = append(t, model.HTTPTest{Name: "Expect-CT (should not exist)", Passed: false, Detail: "Expect-CT present"})
	} else {
		t = append(t, model.HTTPTest{Name: "Expect-CT (should not exist)", Passed: true})
	}
	if h["X-XSS-Protection"] != "" {
		t = append(t, model.HTTPTest{Name: "X-XSS-Protection (should not exist)", Passed: false, Detail: "header present"})
	} else {
		t = append(t, model.HTTPTest{Name: "X-XSS-Protection (should not exist)", Passed: true})
	}
	return t
}

func evalClearSiteData(ctx context.Context, client *http.Client, baseURL, logoutPath string) []model.HTTPTest {
	if logoutPath == "" {
		return []model.HTTPTest{{
			Name: "Clear-Site-Data", Skipped: true, Detail: "provide --logout-path to test logout response",
		}}
	}
	u := strings.TrimSuffix(baseURL, "/") + "/" + logoutPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: false, Detail: err.Error()}}
	}
	req.Header.Set("User-Agent", "recordscan/"+model.Version)
	resp, err := client.Do(req)
	if err != nil {
		return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: false, Detail: err.Error()}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: false, Detail: fmt.Sprintf("logout URL status %d", resp.StatusCode)}}
	}
	v := resp.Header.Get("Clear-Site-Data")
	if v == "" {
		return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: false, Detail: "header missing on logout URL"}}
	}
	// YAML expects '"cache","cookies","storage"'
	if !strings.Contains(v, "cache") || !strings.Contains(v, "cookies") || !strings.Contains(v, "storage") {
		return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: false, Detail: "expected cache, cookies, storage — got " + v}}
	}
	return []model.HTTPTest{{Name: "Clear-Site-Data", Passed: true}}
}
