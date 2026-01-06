package boltdb

import "go.etcd.io/bbolt"

type VulnerabilityRoot vulnerabilityRoot

func (c *Connection) Conn() *bbolt.DB {
	return c.conn
}
