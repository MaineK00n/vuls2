package session

import (
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/cache"
)

func (s *Session) SetStorage(storage Storage) {
	s.storage = storage
}

func (s *Session) SetCache(cache *cache.Cache) {
	s.cache = cache
}

func (s Session) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	return s.getAdvisory(id)
}

func (s Session) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	return s.getVulnerability(id)
}
