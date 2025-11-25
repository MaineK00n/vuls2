package util

import (
	"sync"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Cache struct {
	advisoryCache    *sync.Map
	vulnerabilityMap *sync.Map
}

func NewCache() *Cache {
	return &Cache{
		advisoryCache:    &sync.Map{},
		vulnerabilityMap: &sync.Map{},
	}
}

func (c *Cache) LoadAdvisory(key advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, bool) {
	value, ok := c.advisoryCache.Load(key)
	if ok {
		return value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory), true
	}
	return nil, false
}

func (c *Cache) StoreAdvisory(key advisoryContentTypes.AdvisoryID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory) {
	c.advisoryCache.Store(key, value)
}

func (c *Cache) LoadVulnerability(key vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, bool) {
	value, ok := c.vulnerabilityMap.Load(key)
	if ok {
		return value.(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability), true
	}
	return nil, false
}

func (c *Cache) StoreVulnerability(key vulnerabilityContentTypes.VulnerabilityID, value map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability) {
	c.vulnerabilityMap.Store(key, value)
}
