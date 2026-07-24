package types

import (
	"time"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

type DetectResult struct {
	JSONVersion int    `json:"json_version,omitempty"`
	ServerUUID  string `json:"server_uuid,omitempty"`
	ServerName  string `json:"server_name,omitempty"`

	Detected    []VulnerabilityData          `json:"detected,omitempty"`
	DataSources []datasourceTypes.DataSource `json:"datasources,omitempty"`

	// Warnings aggregates the non-fatal evaluation warnings recorded on the
	// FilteredCriteria trees (e.g. enum values this build could not evaluate
	// — data from a newer vuls-data-update), grouped by data source and
	// warning kind: provenance at the grain that is actionable (which
	// source's data needs a newer build) without per-root noise. The inner
	// slice carries the deduplicated raw Warning.Cause values verbatim, in
	// no guaranteed order (collection traverses maps) — a canonical order,
	// like the rest of rendering, is the presentation layer's job (sort
	// before displaying or comparing) — and an empty string is preserved (for
	// cause-carrying kinds it means the datum was unset; kinds that carry no
	// cause by design, e.g. empty-range, collect [""]) and interpretation is
	// per kind. It is collected before the affected gate prunes not-affected
	// conditions, so a skip stays observable even when the condition
	// carrying it is dropped from Detected. Consumers (e.g. vuls0's
	// ScanResult warnings) can surface these without walking the trees;
	// iterate map keys in sorted order where deterministic output matters.
	Warnings map[sourceTypes.SourceID]map[warningTypes.Kind][]string `json:"warnings,omitempty"`

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
