package common

import (
	"github.com/pkg/errors"
	"github.com/redis/rueidis"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/redis"
	"github.com/MaineK00n/vuls2/pkg/types"
)

const (
	SchemaVersion = 1
)

type DB interface {
	Open() error
	Close() error

	GetMetadata() (*types.Metadata, error)
	PutMetadata(types.Metadata) error

	GetVulnerabilityDetections(string, string) (<-chan struct {
		ID        string
		Detection detectionTypes.Detection
	}, error)
	GetVulnerabilityData(string) (*types.VulnerabilityData, error)
	PutVulnerabilityData(string) error

	GetDataSource(sourceTypes.SourceID) (*datasourceTypes.DataSource, error)
	PutDataSource(string) error

	DeleteAll() error
}

type Config struct {
	Type string
	Path string

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
