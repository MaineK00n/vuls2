package boltdb

import "go.etcd.io/bbolt"

type VulnerabilityRoot vulnerabilityRoot

func (c *Connection) Conn() *bbolt.DB {
	return c.conn
}

func SetPutBatchSize(n int) (restore func()) {
	old := putBatchSize
	putBatchSize = n
	return func() { putBatchSize = old }
}
