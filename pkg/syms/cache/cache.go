package cache

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

type LookupResult struct {
	Symbol string
	Hit    bool
}

type Cache struct {
	cache       *lru.Cache[uint64, string]
	resolveFunc func(addr uint64) string
	evicted     int
}

func New(resolveFunc func(addr uint64) string, size int) *Cache {
	this := &Cache{resolveFunc: resolveFunc}
	this.cache, _ = lru.NewWithEvict[uint64, string](size, func(uint64, string) {
		this.evicted++
	})
	return this
}

func (c *Cache) Lookup(addr uint64) LookupResult {
	if sym, ok := c.cache.Get(addr); ok {
		return LookupResult{Symbol: sym, Hit: true}
	}
	sym := c.resolveFunc(addr)
	c.cache.Add(addr, sym)
	return LookupResult{Symbol: sym, Hit: false}
}

func (c *Cache) TotalEvectied() int { return c.evicted }

func (c *Cache) ResetEvicted() { c.evicted = 0 }
