package types

type ScanResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	Family      string `json:"family,omitempty"`
	Release     string `json:"release,omitempty"`

	Kernel     Kernel      `json:"kernel,omitempty"`
	OSPackages []OSPackage `json:"os_packages,omitempty"`
	CPE        []string    `json:"cpe,omitempty"`

	Optional map[string]interface{} `json:"optional,omitempty"`
	Config   interface{}            `json:"config,omitempty"`
}

type Kernel struct {
	Release        string `json:"release,omitempty"`
	Version        string `json:"version,omitempty"`
	RebootRequired bool   `json:"reboot_required,omitempty"`
}

type OSPackage struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	Release         string `json:"release,omitempty"`
	NewVersion      string `json:"new_version,omitempty"`
	NewRelease      string `json:"new_release,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Repository      string `json:"repository,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`
	SrcName         string `json:"src_name,omitempty"`
	SrcVersion      string `json:"src_version,omitempty"`
}
