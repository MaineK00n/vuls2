package rdb

import (
	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/types"
)

type Config struct {
	Type string
	Path string
}

type Connection struct {
	Config *Config

	conn *gorm.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	switch c.Config.Type {
	case "sqlite3":
		db, err := gorm.Open(sqlite.Open(c.Config.Path))
		if err != nil {
			return errors.WithStack(err)
		}
		c.conn = db
		return nil
	case "mysql":
		db, err := gorm.Open(mysql.Open(c.Config.Path))
		if err != nil {
			return errors.WithStack(err)
		}
		c.conn = db
		return nil
	case "postgres":
		db, err := gorm.Open(postgres.Open(c.Config.Path))
		if err != nil {
			return errors.WithStack(err)
		}
		c.conn = db
		return nil
	default:
		return errors.Errorf("%s is not support rdb dbtype", c.Config.Type)
	}
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	db, err := c.conn.DB()
	if err != nil {
		return errors.Wrap(err, "get *sql.DB")
	}
	return db.Close()
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
