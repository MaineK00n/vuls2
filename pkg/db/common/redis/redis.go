package redis

import (
	"iter"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type Connection struct {
	Config *rueidis.ClientOption

	conn rueidis.Client
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	client, err := rueidis.NewClient(*c.Config)
	if err != nil {
		return errors.WithStack(err)
	}
	c.conn = client
	return nil
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	c.conn.Close()
	return nil
}

func (c *Connection) GetMetadata() (*db.Metadata, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutMetadata(metadata db.Metadata) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityData(searchType db.SearchType, queries ...string) iter.Seq2[db.VulnerabilityData, error] {
	return func(yield func(db.VulnerabilityData, error) bool) {
		if !yield(db.VulnerabilityData{}, errors.New("not implemented yet")) {
			return
		}
	}
}

func (c *Connection) PutVulnerabilityData(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetRoot(id dataTypes.RootID) (*db.VulnerabilityData, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetEcosystems() ([]ecosystemTypes.Ecosystem, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetIndexes(ecosystem ecosystemTypes.Ecosystem, queries ...string) (map[dataTypes.RootID][]string, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutDataSource(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) DeleteAll() error {
	return errors.New("not implemented yet")
}

func (c *Connection) Initialize() error {
	return errors.New("not implemented yet")
}
