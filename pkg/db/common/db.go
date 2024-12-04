package common

import (
	"github.com/pkg/errors"
	"github.com/redis/rueidis"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/redis"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

const (
	SchemaVersion = 1
)

type DB interface {
	Open() error
	Close() error

	GetMetadata() (*dbTypes.Metadata, error)
	PutMetadata(dbTypes.Metadata) error

	GetVulnerabilityDetections(dbTypes.SearchDetectionType, ...string) (<-chan dbTypes.VulnerabilityDataDetection, <-chan error)
	GetVulnerabilityData(dbTypes.SearchDataType, string) (*dbTypes.VulnerabilityData, error)
	PutVulnerabilityData(string) error

	GetDataSource(sourceTypes.SourceID) (*datasourceTypes.DataSource, error)
	PutDataSource(string) error

	DeleteAll() error
	Initialize() error
}

type Config struct {
	Type  string
	Path  string
	Debug bool
}

func (c *Config) New() (DB, error) {
	switch c.Type {
	case "boltdb":
		return &boltdb.Connection{Config: &boltdb.Config{Path: c.Path}}, nil
	case "redis":
		return &redis.Connection{Config: &rueidis.ClientOption{InitAddress: []string{c.Path}}}, nil
	case "sqlite3", "mysql", "postgres":
		return &rdb.Connection{Config: &rdb.Config{Type: c.Type, Path: c.Path}}, nil
	default:
		return nil, errors.Errorf("%s is not support dbtype", c.Type)
	}
}
