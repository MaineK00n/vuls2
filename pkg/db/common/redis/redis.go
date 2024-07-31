package redis

import (
	"github.com/pkg/errors"
	"github.com/redis/rueidis"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
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

func (c *Connection) GetVulnerabilityDetections(searchType dbTypes.SearchDetectionType, queries ...string) (<-chan dbTypes.VulnerabilityDataDetection, <-chan error) {
	resCh := make(chan dbTypes.VulnerabilityDataDetection, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(resCh)
		defer close(errCh)

		errCh <- errors.New("not implemented yet")
	}()

	return resCh, errCh
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchDataType, id string) (*dbTypes.VulnerabilityData, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutVulnerabilityData(root string) error {
	return errors.New("not implemented yet")
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
