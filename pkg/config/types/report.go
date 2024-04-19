package types

type ReportConfig struct {
	Stdout *struct {
		Format string `json:"format"` // oneline, full-text
	} `json:"stdout"`
	CSV           *struct{} `json:"csv"`
	XML           *struct{} `json:"xml"`
	CycloneDXJSON *struct{}
	CycloneDXXML  *struct{}
	SPDXJSON      *struct{}
	SPDXXML       *struct{}
	HTTP          map[string]struct {
		Format string `json:"format"` // oneline, full-text
		URL    string `json:"url"`
	} `json:"http"`
	EMail map[string]struct {
		Format        string   `json:"format"`   // oneline, full-text
		TLSMode       string   `json:"tls_mode"` // None, STARTTLS, SMTPS
		SMTPAddress   string   `json:"smtp_address"`
		SMTPPort      int      `json:"smtp_port"`
		User          string   `json:"user"`
		Password      string   `json:"password"`
		From          string   `json:"from"`
		To            []string `json:"to"`
		CC            []string `json:"cc"`
		SubjectPrefix string   `json:"subject_prefix"`
	} `json:"email"`
	Syslog map[string]struct {
		Format   string `json:"format"` // oneline, full-text
		Protocol string `json:"protocol"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Tag      string `json:"tag"`
		Facility string `json:"facility"`
		Severity string `json:"severity"`
		Verbose  bool   `json:"verbose"`
	} `json:"syslog"`
	Slack map[string]struct {
		Format      string   `json:"format"` // oneline, full-text
		HookURL     string   `json:"hook_url"`
		LegacyToken string   `json:"legacy_token"`
		Channel     string   `json:"channel"`
		IconEmoji   string   `json:"icon_emoji"`
		AuthUser    string   `json:"auth_user"`
		NotifyUsers []string `json:"notify_users"`
	} `json:"slack"`
	ChatWork map[string]struct {
		Format string `json:"format"` // oneline, full-text
		Room   string `json:"room"`
		Token  string `json:"token"`
	} `json:"chatwork"`
	Telegram map[string]struct {
		Format string `json:"format"` // oneline, full-text
		ChatID string `json:"chat_id"`
		Token  string `json:"token"`
	} `json:"telegram"`
	S3        map[string]struct{} `json:"s3"`
	GCS       map[string]struct{} `json:"gcs"`
	AzureBlob map[string]struct{} `json:"azure_blob"`
}
