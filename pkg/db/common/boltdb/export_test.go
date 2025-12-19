package boltdb

import "github.com/MaineK00n/vuls2/pkg/db/common/util"

func (c *Connection) SetCache(cache *util.Cache) {
	c.cache = cache
}
