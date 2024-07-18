package redis

import (
	"github.com/pkg/errors"
	"github.com/redis/rueidis"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/types"
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

func (c *Connection) GetMetadata() (*types.Metadata, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutMetadata(metadata types.Metadata) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityDetections(ecosystem, key string) (<-chan struct {
	ID        string
	Detection detectionTypes.Detection
}, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityData(id string) (*types.VulnerabilityData, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutVulnerabilityData(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetDataSource(id source.SourceID) (*datasourceTypes.DataSource, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutDataSource(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) DeleteAll() error {
	return errors.New("not implemented yet")
}
