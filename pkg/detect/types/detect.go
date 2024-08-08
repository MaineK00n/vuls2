package types

import (
	"time"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	dbtypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type DetectResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`

	Detected    map[string]dbtypes.VulnerabilityData `json:"detected,omitempty"`
	DataSources []datasourceTypes.DataSource         `json:"data_sources,omitempty"`

	DetectedAt time.Time `json:"detected_at,omitempty"`
	DetectedBy string    `json:"detected_by,omitempty"`
}
