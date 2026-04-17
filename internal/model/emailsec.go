package model

// EmailSecReport is a dedicated email authentication and transport-security assessment.
type EmailSecReport struct {
	Metadata  ScanMetadata       `json:"metadata"`
	Zone      string             `json:"zone"`
	MX        []EmailMXRow       `json:"mx,omitempty"`
	SPF       *EmailSPFSection   `json:"spf,omitempty"`
	DMARC     *EmailDMARCSection `json:"dmarc,omitempty"`
	DKIM      []EmailDKIMRow     `json:"dkim,omitempty"`
	MTASTS    *EmailMTASTSBlock  `json:"mta_sts,omitempty"`
	TLSRPT    *EmailTLSRPTBlock  `json:"tls_rpt,omitempty"`
	BIMI      *EmailBIMIBlock    `json:"bimi,omitempty"`
	Controls  []EmailControl     `json:"controls"`
	Findings  []Finding          `json:"findings"`
	Summary   EmailSecSummary    `json:"summary"`
	Technical map[string]any     `json:"technical_detail,omitempty"`
}

type EmailSecSummary struct {
	PostureScore    int            `json:"posture_score"`
	PostureLabel    string         `json:"posture_label"`
	ControlsPass    int            `json:"controls_pass"`
	ControlsWarn    int            `json:"controls_warn"`
	ControlsFail    int            `json:"controls_fail"`
	FindingsTotal   int            `json:"findings_total"`
	BySeverity      map[string]int `json:"by_severity"`
	MXCount         int            `json:"mx_count"`
	DKIMPublishers  int            `json:"dkim_publishers_found"`
	HasSPF          bool           `json:"has_spf"`
	HasDMARC        bool           `json:"has_dmarc"`
	MTASTSEnabled   bool           `json:"mta_sts_enabled"`
	TLSRPTPublished bool           `json:"tls_rpt_published"`
}

type EmailMXRow struct {
	Priority int      `json:"priority"`
	Host     string   `json:"host"`
	Resolved []string `json:"resolved,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

type EmailSPFSection struct {
	RawRecords     []string `json:"raw_records,omitempty"`
	PrimaryRecord  string   `json:"primary_record,omitempty"`
	LookupEstimate int      `json:"lookup_estimate"`
	LookupDetail   string   `json:"lookup_detail,omitempty"`
	EndsWithAll    string   `json:"ends_with_all,omitempty"` // -all, ~all, ?all, +all, none
	HasPTR         bool     `json:"has_ptr_mechanism"`
	HasRedirect    bool     `json:"has_redirect"`
	RedirectTarget string   `json:"redirect_target,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

type EmailDMARCSection struct {
	RawRecords []string          `json:"raw_records,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Policy     string            `json:"policy,omitempty"`           // p=
	Subpolicy  string            `json:"subdomain_policy,omitempty"` // sp=
	Pct        string            `json:"pct,omitempty"`
	RUA        string            `json:"rua,omitempty"`
	RUF        string            `json:"ruf,omitempty"`
	ADKIM      string            `json:"adkim,omitempty"`
	ASPF       string            `json:"aspf,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

type EmailDKIMRow struct {
	Selector string   `json:"selector"`
	Found    bool     `json:"found"`
	Records  []string `json:"records,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

type EmailMTASTSBlock struct {
	TXTRecord   string `json:"txt_record,omitempty"`
	ID          string `json:"id,omitempty"`
	PolicyURL   string `json:"policy_url,omitempty"`
	PolicyBody  string `json:"policy_body,omitempty"`
	PolicyFetch string `json:"policy_fetch_error,omitempty"`
	Mode        string `json:"mode,omitempty"` // enforce, testing, none
	MaxAge      string `json:"max_age,omitempty"`
	MXPatterns  string `json:"mx_patterns,omitempty"`
}

type EmailTLSRPTBlock struct {
	TXTRecord string `json:"txt_record,omitempty"`
	RUA       string `json:"rua,omitempty"`
}

type EmailBIMIBlock struct {
	TXTRecord string `json:"txt_record,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// EmailControl is a single enterprise-style control row (pass / warn / fail).
type EmailControl struct {
	ID     string `json:"id"`
	Area   string `json:"area"`
	Title  string `json:"title"`
	Status string `json:"status"` // pass, warn, fail
	Detail string `json:"detail,omitempty"`
}
