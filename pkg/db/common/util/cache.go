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
	value, ok := c.advisories.Load(key)
	if ok {
		return value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory), true
	}
	return nil, false
}

func (c *Cache) StoreAdvisory(key advisoryContentTypes.AdvisoryID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory) {
	c.advisories.Store(key, value)
}

func (c *Cache) LoadVulnerability(key vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, bool) {
	value, ok := c.vulnerabilities.Load(key)
	if ok {
		return value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability), true
	}
	return nil, false
}

func (c *Cache) StoreVulnerability(key vulnerabilityContentTypes.VulnerabilityID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability) {
	c.vulnerabilities.Store(key, value)
}
