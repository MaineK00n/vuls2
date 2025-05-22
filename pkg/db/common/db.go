package common

import (
	"iter"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"
	bolt "go.etcd.io/bbolt"
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
	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/redis"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

const (
	SchemaVersion = 0
)

type DB interface {
	Open() error
	Close() error

	GetMetadata() (*dbTypes.Metadata, error)
	PutMetadata(dbTypes.Metadata) error

	GetVulnerabilityData(dbTypes.SearchType, ...string) iter.Seq2[dbTypes.VulnerabilityData, error]
	PutVulnerabilityData(string) error
	GetRoot(dataTypes.RootID) (*dbTypes.VulnerabilityData, error)
	GetAdvisory(advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error)
	GetVulnerability(vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error)
	GetEcosystems() ([]ecosystemTypes.Ecosystem, error)
	GetIndexes(ecosystemTypes.Ecosystem, ...string) (map[dataTypes.RootID][]string, error)
	GetDetection(ecosystemTypes.Ecosystem, dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error)

	GetDataSources() ([]datasourceTypes.DataSource, error)
	GetDataSource(sourceTypes.SourceID) (*datasourceTypes.DataSource, error)
	PutDataSource(string) error

	DeleteAll() error
	Initialize() error
}

type Config struct {
	Type    string
	Path    string
	Debug   bool
	Options DBOptions
}

type DBOptions struct {
	BoltDB *bolt.Options
	Redis  *rueidis.ClientOption
	RDB    []gorm.Option
}

func (c *Config) New() (DB, error) {
	switch c.Type {
	case "boltdb":
		return &boltdb.Connection{Config: &boltdb.Config{Path: c.Path, Options: c.Options.BoltDB}}, nil
	case "redis":
		conf := c.Options.Redis
		if conf == nil {
			conf = &rueidis.ClientOption{InitAddress: []string{c.Path}}
		}
		return &redis.Connection{Config: conf}, nil
	case "sqlite3", "mysql", "postgres":
		return &rdb.Connection{Config: &rdb.Config{Type: c.Type, Path: c.Path, Options: c.Options.RDB}}, nil
	default:
		return nil, errors.Errorf("%s is not support dbtype", c.Type)
	}
}
