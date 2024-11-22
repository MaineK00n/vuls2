package redis

import (
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type vulnerabilityRoot struct {
	ID              dataTypes.RootID                            `json:"id,omitempty"`
	Advisories      []advisoryContentTypes.AdvisoryID           `json:"advisories,omitempty"`
	Vulnerabilities []vulnerabilityContentTypes.VulnerabilityID `json:"vulnerabilities,omitempty"`
	Ecosystems      []ecosystemTypes.Ecosystem                  `json:"ecosystems,omitempty"`
	DataSources     []sourceTypes.SourceID                      `json:"data_sources,omitempty"`
}
