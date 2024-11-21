package types

import (
	"time"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type DetectResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`

	Detected    []VulnerabilityData          `json:"detected,omitempty"`
	DataSources []datasourceTypes.DataSource `json:"data_sources,omitempty"`

	DetectedAt time.Time `json:"detected_at,omitempty"`
	DetectedBy string    `json:"detected_by,omitempty"`
}

type VulnerabilityData struct {
	ID              string                                   `json:"id,omitempty"`
	Advisories      []dbTypes.VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []dbTypes.VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection             `json:"detections,omitempty"`
}

type VulnerabilityDataDetection struct {
	Ecosystem ecosystemTypes.Ecosystem                                             `json:"ecosystem,omitempty"`
	Contents  map[string]map[sourceTypes.SourceID]conditionTypes.FilteredCondition `json:"contents,omitempty"`
}
