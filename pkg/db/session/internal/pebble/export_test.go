package pebble

import "github.com/cockroachdb/pebble"

type VulnerabilityRoot vulnerabilityRoot

func (c *Connection) Conn() *pebble.DB {
	return c.conn
}
