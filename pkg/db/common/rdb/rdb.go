package rdb

import (
	"iter"

	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
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
	return db.Close()
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchType, queries ...string) iter.Seq2[dbTypes.VulnerabilityData, error] {
	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		if !yield(dbTypes.VulnerabilityData{}, errors.New("not implemented yet")) {
			return
		}
	}
}

func (c *Connection) PutVulnerabilityData(root string) error {
	return errors.New("not implemented yet")
}

func (c *Connection) GetRoot(rootID dataTypes.RootID) (*dbTypes.VulnerabilityData, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetAdvisory(advisoryID advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetVulnerability(vulnerabilityID vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
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
