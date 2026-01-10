package cache

import "sync"

func (c *Cache) GetAdvisories() *sync.Map {
	return c.advisories
}

func (c *Cache) GetVulnerabilities() *sync.Map {
	return c.vulnerabilities
}
