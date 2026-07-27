package types

import (
	"time"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/types/warning"
)

type DetectResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`

	Detected    []VulnerabilityData          `json:"detected,omitempty"`
	DataSources []datasourceTypes.DataSource `json:"datasources,omitempty"`

	// Warnings aggregates the non-fatal evaluation warnings recorded on the
	// FilteredCriteria trees (e.g. enum values this build could not evaluate
	// — data from a newer vuls-data-update), deduplicated on the whole entry
	// and in no guaranteed order (collection traverses maps) — grouping and
	// ordering, like the rest of rendering, are the presentation layer's
	// job. It is collected before the affected gate prunes not-affected
	// conditions, so a skip stays observable even when the condition
	// carrying it is dropped from Detected: for conditions that survive the
	// gate this aggregate duplicates the tree, but for pruned ones it is the
	// only carrier. Consumers (e.g. vuls0's ScanResult warnings) can surface
	// these without walking the trees.
	Warnings []warning.Warning `json:"warnings,omitempty"`

	DetectedAt time.Time `json:"detected_at,omitzero"`
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
