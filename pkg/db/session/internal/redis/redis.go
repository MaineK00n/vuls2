package redis

import (
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
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

const (
	SchemaVersion = 0
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

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return errors.New("not implemented yet")
}

func (c *Connection) Put(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetRoot(id dataTypes.RootID) (dbTypes.VulnerabilityData, error) {
	return dbTypes.VulnerabilityData{}, errors.New("not implemented yet")
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

func (c *Connection) GetIndex(ecosystem ecosystemTypes.Ecosystem, query string) ([]dataTypes.RootID, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (datasourceTypes.DataSource, error) {
	return datasourceTypes.DataSource{}, errors.New("not implemented yet")
}

func (c *Connection) DeleteAll() error {
	return errors.New("not implemented yet")
}

func (c *Connection) Initialize() error {
	return errors.New("not implemented yet")
}
