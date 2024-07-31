package boltdb

type vulnerabilityRoot struct {
	ID              string   `json:"id,omitempty"`
	Advisories      []string `json:"advisories,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Ecosystems      []string `json:"ecosystems,omitempty"`
	DataSources     []string `json:"data_sources,omitempty"`
}
