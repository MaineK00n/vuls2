package config

type Config struct {
	Scan   *Scan           `json:"scan"`
	Detect *Detect         `json:"detect"`
	Report *Report         `json:"report"`
	Server *Server         `json:"server"`
	Hosts  map[string]Host `json:"hosts"`
}

type Scan struct {
	OSPkg          *scanOSPkg     `json:"ospkg,omitempty"`
	LangPkg        *scanLangPkg   `json:"langpkg,omitempty"`
	Lockfile       *scanLockfile  `json:"lockfile,omitempty"`
	WordPress      *scanWordPress `json:"wordpress,omitempty"`
	CPE            []scanCPE      `json:"cpe,omitempty"`
	SBOMComponents []string       `json:"sbom_components,omitempty"`
	Port           *scanPort      `json:"port,omitempty"`
	TimeoutUnit    int            `json:"timeout_unit,omitempty"`
	TimeoutScan    int            `json:"timeout_scan,omitempty"`
	ResultDir      string         `json:"result_dir,omitempty"`
	LogDir         string         `json:"log_dir,omitempty"`
	Debug          bool           `json:"debug,omitempty"`
}

type scanOSPkg struct {
	Root    bool `json:"root"`
	Offline bool `json:"offline"`
}

type scanLangPkg struct{}

type scanLockfile struct {
	Find bool     `json:"find,omitempty"`
	Path []string `json:"path,omitempty"`
}

type scanWordPress struct {
	Root    string `json:"root"`
	Path    string `json:"path"`
	User    string `json:"user"`
	DocRoot string `json:"doc_root"`
}

type scanCPE struct {
	CPE       string `json:"cpe,omitempty"`
	RunningOn string `json:"running_on,omitempty"`
}

type scanPort struct {
	Type string        `json:"type,omitempty"`
	Nmap *scanPortNmap `json:"nmap,omitempty"`
}

type scanPortNmap struct{}

type Detect struct {
	Path      string    `json:"path"`
	CPE       detectCPE `json:"cpe"`
	ResultDir string    `json:"result_dir"`
	LogDir    string    `json:"log_dir"`
	Debug     bool      `json:"debug"`
}

type detectCPE struct {
	Match string `json:"match,omitempty"`
}

type Report struct {
	Stdout     string            `json:"stdout"`
	Localfile  []string          `json:"localfile"`
	AWS        *reportAWS        `json:"aws"`
	GCP        *reportGCP        `json:"gcp"`
	Azure      *reportAzure      `json:"azure"`
	Syslog     *reportSyslog     `json:"syslog"`
	HTTP       *reportHTTP       `json:"http"`
	EMail      *reportEMail      `json:"email"`
	Slack      *reportSlack      `json:"slack"`
	Chatwork   *reportChatwork   `json:"chatwork"`
	Googlechat *reportGoogleChat `json:"googlechat"`
	Telegram   *reportTelegram   `json:"telegram"`
	Ignore     *reportIgnore     `json:"ignore"`
	ResultDir  string            `json:"result_dir"`
	LogDir     string            `json:"log_dir"`
	Debug      bool              `json:"debug"`
}

type reportAWS struct{}

type reportGCP struct{}

type reportAzure struct{}

type reportSyslog struct{}

type reportHTTP struct{}

type reportEMail struct{}

type reportSlack struct{}

type reportChatwork struct{}

type reportGoogleChat struct{}

type reportTelegram struct{}

type reportIgnore struct {
	CVSSunder *float64 `json:"cvss_under,omitempty"`
	ID        []string `json:"id,omitempty"`
	Package   []string `json:"package,omitempty"`
}

type Server struct {
	Listen string        `json:"listen"`
	Path   string        `json:"path"`
	Scan   *serverScan   `json:"scan"`
	Detect *serverDetect `json:"detect"`
	Report *serverReport `json:"report"`
	LogDir string        `json:"log_dir"`
	Debug  bool          `json:"debug"`
}

type serverScan struct {
	Compress string `json:"compress,omitempty"`
}

type serverDetect struct {
	Compress string `json:"compress,omitempty"`
}

type serverReport struct {
	Format   string `json:"format,omitempty"`
	Compress string `json:"compress,omitempty"`
}

type Host struct {
	Type      string  `json:"type"`
	Host      *string `json:"host"`
	Port      *string `json:"port"`
	User      *string `json:"user"`
	SSHConfig *string `json:"ssh_config"`
	SSHKey    *string `json:"ssh_key"`
	Scan      *Scan   `json:"scan"`
	Detect    *Detect `json:"detect"`
	Report    *Report `json:"report"`
}
