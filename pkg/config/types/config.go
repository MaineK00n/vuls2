package types

type Config struct {
	Scan   *ScanConfig           `json:"scan"`
	Detect *DetectConfig         `json:"detect"`
	Report *ReportConfig         `json:"report"`
	Server *ServerConfig         `json:"server"`
	Hosts  map[string]HostConfig `json:"hosts"`
}
