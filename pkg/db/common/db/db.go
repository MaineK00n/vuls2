package db

import (
	"github.com/pkg/errors"
	"github.com/redis/rueidis"
	bolt "go.etcd.io/bbolt"
	"gorm.io/gorm"

	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/redis"
)

const (
	SchemaVersion = 0
)

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

func (c *Config) New() (Connection, error) {
	switch c.Type {
	case "boltdb":
		return &boltdb.Connection{Config: &boltdb.Config{Path: c.Path, Options: c.Options.BoltDB}}, nil
	case "redis":
		conf := c.Options.Redis
		if conf == nil {
			c, err := rueidis.ParseURL(c.Path)
			if err != nil {
				return nil, errors.Wrap(err, "parse redis url")
			}
			conf = &c
		}
		return &redis.Connection{Config: conf}, nil
	case "sqlite3", "mysql", "postgres":
		return &rdb.Connection{Config: &rdb.Config{Type: c.Type, Path: c.Path, Options: c.Options.RDB}}, nil
	default:
		return nil, errors.Errorf("%s is not support dbtype", c.Type)
	}
}
