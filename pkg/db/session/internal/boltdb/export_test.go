package boltdb

import (
	"errors"

	"go.etcd.io/bbolt"
)

type VulnerabilityRoot vulnerabilityRoot

func (c *Connection) Conn() *bbolt.DB {
	return c.conn
}

func SetPutBatchSize(n int) (restore func(), err error) {
	if n <= 0 {
		return nil, errors.New("putBatchSize must be positive")
	}
	old := putBatchSize
	putBatchSize = n
	return func() { putBatchSize = old }, nil
}
