package model

const Version = "0.1.0"

type ScanMetadata struct {
	ToolVersion  string `json:"tool_version"`
	TargetHost   string `json:"target_host"`
	ScannedAtUTC string `json:"scanned_at_utc"`
	Elapsed      string `json:"elapsed"`
	OutDir       string `json:"out_dir"`
}

// Finding is a single security or configuration observation.
type Finding struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"` // critical, high, medium, low, info, pass
	Title          string   `json:"title"`
	Detail         string   `json:"detail,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

type ScanReport struct {
	Metadata ScanMetadata `json:"metadata"`
	DNS      DNSReport    `json:"dns"`
	SSL      SSLReport    `json:"ssl"`
	HTTP     HTTPReport   `json:"http"`
	Summary  ScanSummary  `json:"summary"`
}

type ScanSummary struct {
	FindingsTotal       int            `json:"findings_total"`
	BySeverity          map[string]int `json:"by_severity"`
	DNSFindingCount     int            `json:"dns_finding_count"`
	SSLFindingCount     int            `json:"ssl_finding_count"`
	HTTPFindingCount    int            `json:"http_finding_count"`
	HTTPTestsPassed     int            `json:"http_tests_passed"`
	HTTPTestsFailed     int            `json:"http_tests_failed"`
	HTTPTestsSkipped    int            `json:"http_tests_skipped"`
	SSLGrade            string         `json:"ssl_grade,omitempty"`
	SSLProtocolScore    int            `json:"ssl_protocol_score,omitempty"`
	SSLCertificateScore int            `json:"ssl_certificate_score,omitempty"`
}

type DNSReport struct {
	Zone            string              `json:"zone"`
	Nameservers     []string            `json:"nameservers,omitempty"`
	RawRecords      map[string][]string `json:"raw_records,omitempty"`
	TechnicalDetail map[string]any      `json:"technical_detail,omitempty"`
	Findings        []Finding           `json:"findings"`
}

type SSLReport struct {
	Host                 string              `json:"host"`
	Port                 int                 `json:"port"`
	Connected            bool                `json:"connected"`
	NegotiatedVersion    string              `json:"negotiated_version,omitempty"`
	NegotiatedCipher     string              `json:"negotiated_cipher,omitempty"`
	Certificate          *CertificateSummary `json:"certificate,omitempty"`
	SupportedProtocols   []string            `json:"supported_protocols,omitempty"`
	WeakProtocolsEnabled []string            `json:"weak_protocols_enabled,omitempty"`
	SupportedCiphers     []CipherProbe       `json:"supported_ciphers,omitempty"`
	Grading              *SSLGrading         `json:"grading,omitempty"`
	Findings             []Finding           `json:"findings"`
	Error                string              `json:"error,omitempty"`
}

type CertificateSummary struct {
	SubjectCN          string   `json:"subject_cn,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IssuerCN           string   `json:"issuer_cn,omitempty"`
	NotBeforeUTC       string   `json:"not_before_utc,omitempty"`
	NotAfterUTC        string   `json:"not_after_utc,omitempty"`
	DaysUntilExpiry    int      `json:"days_until_expiry,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	VerifiedChain      bool     `json:"verified_chain,omitempty"`
	HostnameMatch      bool     `json:"hostname_match,omitempty"`
}

type CipherProbe struct {
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
	ID       uint16 `json:"id"`
	Score    int    `json:"score"`
}

type SSLGrading struct {
	OverallGrade     string `json:"overall_grade"`
	ProtocolScore    int    `json:"protocol_score"`
	CertificateScore int    `json:"certificate_score"`
	CipherScore      int    `json:"cipher_score"`
	OverallScore     int    `json:"overall_score"`
	Notes            string `json:"notes,omitempty"`
}

type HTTPReport struct {
	BaseURL    string       `json:"base_url"`
	LogoutURL  string       `json:"logout_url,omitempty"`
	StatusCode int          `json:"status_code"`
	FinalURL   string       `json:"final_url,omitempty"`
	Headers    HTTPHeaderKV `json:"headers,omitempty"`
	Tests      []HTTPTest   `json:"tests"`
	Findings   []Finding    `json:"findings"`
	Error      string       `json:"error,omitempty"`
}

// HTTPHeaderKV stores canonical header names for stable JSON keys.
type HTTPHeaderKV map[string]string

type HTTPTest struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Skipped  bool   `json:"skipped"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
}
