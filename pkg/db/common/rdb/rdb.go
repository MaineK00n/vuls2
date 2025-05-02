package rdb

import (
	"iter"

	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type Config struct {
	Type string
	Path string

	Options []gorm.Option
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
		db, err := gorm.Open(sqlite.Open(c.Config.Path), c.Config.Options...)
		if err != nil {
			return errors.WithStack(err)
		}
		c.conn = db
		return nil
	case "mysql":
		db, err := gorm.Open(mysql.Open(c.Config.Path), c.Config.Options...)
		if err != nil {
			return errors.WithStack(err)
		}
		c.conn = db
		return nil
	case "postgres":
		db, err := gorm.Open(postgres.Open(c.Config.Path), c.Config.Options...)
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
	return db.Close() //nolint:errcheck
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityDetections(searchType dbTypes.SearchDetectionType, queries ...string) iter.Seq2[dbTypes.VulnerabilityDataDetection, error] {
	return func(yield func(dbTypes.VulnerabilityDataDetection, error) bool) {
		if !yield(dbTypes.VulnerabilityDataDetection{}, errors.New("not implemented yet")) {
			return
		}
	}
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
