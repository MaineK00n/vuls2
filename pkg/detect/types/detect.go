package types

import (
	"time"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
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
	DataSources []datasourceTypes.DataSource `json:"datasources,omitempty"`

	DetectedAt time.Time `json:"detected_at,omitempty"`
	DetectedBy string    `json:"detected_by,omitempty"`
}

type VulnerabilityData struct {
	ID              dataTypes.RootID                         `json:"id,omitempty"`
	Advisories      []dbTypes.VulnerabilityDataAdvisory      `json:"advisories,omitempty"`
	Vulnerabilities []dbTypes.VulnerabilityDataVulnerability `json:"vulnerabilities,omitempty"`
	Detections      []VulnerabilityDataDetection             `json:"detections,omitempty"`
}

type VulnerabilityDataDetection struct {
	Ecosystem ecosystemTypes.Ecosystem                                    `json:"ecosystem,omitempty"`
	Contents  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition `json:"contents,omitempty"`
}
