package util

import (
	"sync"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Cache struct {
	advisories      *sync.Map
	vulnerabilities *sync.Map
}

func NewCache() *Cache {
	return &Cache{
		advisories:      &sync.Map{},
		vulnerabilities: &sync.Map{},
	}
}

func (c *Cache) Close() {
	if c == nil {
		return
	}

	c.advisories = nil
	c.vulnerabilities = nil
}

func (c *Cache) LoadAdvisory(key advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, bool) {
	if c == nil || c.advisories == nil {
		return nil, false
	}

	value, ok := c.advisories.Load(key)
	if !ok {
		return nil, false
	}

	as, ok := value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
	if !ok {
		return nil, false
	}

	return as, true
}

func (c *Cache) StoreAdvisory(key advisoryContentTypes.AdvisoryID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory) {
	if c == nil || c.advisories == nil {
		return
	}

	c.advisories.Store(key, value)
}

func (c *Cache) LoadVulnerability(key vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, bool) {
	if c == nil || c.vulnerabilities == nil {
		return nil, false
	}

	value, ok := c.vulnerabilities.Load(key)
	if !ok {
		return nil, false
	}

	vs, ok := value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
	if !ok {
		return nil, false
	}

	return vs, true
}

func (c *Cache) StoreVulnerability(key vulnerabilityContentTypes.VulnerabilityID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability) {
	if c == nil || c.vulnerabilities == nil {
		return
	}

	c.vulnerabilities.Store(key, value)
}
