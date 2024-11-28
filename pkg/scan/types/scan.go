package types

import "time"

type ScanResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	Family      string `json:"family,omitempty"`
	Release     string `json:"release,omitempty"`

	Kernel     Kernel      `json:"kernel,omitempty"`
	OSPackages []OSPackage `json:"os_packages,omitempty"`
	CPE        []string    `json:"cpe,omitempty"`

	Optional  map[string]interface{} `json:"optional,omitempty"`
	Config    interface{}            `json:"config,omitempty"`
	ScannedAt time.Time              `json:"scanned_at,omitempty"`
	ScannedBy string                 `json:"scanned_by,omitempty"`
}

type Kernel struct {
	Release        string `json:"release,omitempty"`
	Version        string `json:"version,omitempty"`
	RebootRequired bool   `json:"reboot_required,omitempty"`
}

type OSPackage struct {
	Name            string `json:"name,omitempty"`
	Epoch           *int   `json:"epoch,omitempty"`
	Version         string `json:"version,omitempty"`
	Release         string `json:"release,omitempty"`
	NewVersion      string `json:"new_version,omitempty"`
	NewRelease      string `json:"new_release,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Repository      string `json:"repository,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`
	SrcName         string `json:"src_name,omitempty"`
	SrcEpoch        *int   `json:"src_epoch,omitempty"`
	SrcVersion      string `json:"src_version,omitempty"`
	SrcRelease      string `json:"src_release,omitempty"`
}
