package store

import (
	"container/list"
	"sync"
	"time"
)

type lruEntry struct {
	ip        string
	expiresAt *time.Time // nil denotes permanent ban
}

// MemoryStore provides a high-performance in-memory LRU BanStore.
type MemoryStore struct {
	mu          sync.RWMutex
	maxCapacity int
	defaultTTL  time.Duration
	items       map[string]*list.Element
	evictList   *list.List
}

// NewMemoryStore initializes a memory store capped at maxCapacity entries (default: 25,000).
func NewMemoryStore(maxCapacity int, defaultTTL time.Duration) *MemoryStore {
	if maxCapacity <= 0 {
		maxCapacity = 25000
	}
	if defaultTTL <= 0 {
		defaultTTL = time.Hour
	}
	return &MemoryStore{
		maxCapacity: maxCapacity,
		defaultTTL:  defaultTTL,
		items:       make(map[string]*list.Element),
		evictList:   list.New(),
	}
}

// Size returns the active number of tracked entries.
func (s *MemoryStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// IsBanned checks if an IP is currently banned, auto-evicting expired keys.
func (s *MemoryStore) IsBanned(ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	elem, exists := s.items[ip]
	if !exists {
		return false, nil
	}

	entry := elem.Value.(*lruEntry)
	now := time.Now()

	if entry.expiresAt != nil && now.After(*entry.expiresAt) {
		// Key expired: remove immediately
		s.evictList.Remove(elem)
		delete(s.items, ip)
		return false, nil
	}

	// Move to front (Most Recently Used)
	s.evictList.MoveToFront(elem)
	return true, nil
}

// Ban registers a ban for the given IP address.
func (s *MemoryStore) Ban(ip string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	effectiveTTL := ttl
	if effectiveTTL <= 0 && ttl != 0 {
		effectiveTTL = s.defaultTTL
	}

	var expiresAt *time.Time
	if effectiveTTL > 0 {
		t := time.Now().Add(effectiveTTL)
		expiresAt = &t
	}

	// If entry already exists, update expiration and move to front
	if elem, exists := s.items[ip]; exists {
		entry := elem.Value.(*lruEntry)
		entry.expiresAt = expiresAt
		s.evictList.MoveToFront(elem)
		return nil
	}

	// Capacity enforcement: evict oldest entry if at capacity
	if s.evictList.Len() >= s.maxCapacity {
		oldest := s.evictList.Back()
		if oldest != nil {
			s.evictList.Remove(oldest)
			delete(s.items, oldest.Value.(*lruEntry).ip)
		}
	}

	newEntry := &lruEntry{
		ip:        ip,
		expiresAt: expiresAt,
	}
	elem := s.evictList.PushFront(newEntry)
	s.items[ip] = elem
	return nil
}

// Unban removes an IP address from the store.
func (s *MemoryStore) Unban(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if elem, exists := s.items[ip]; exists {
		s.evictList.Remove(elem)
		delete(s.items, ip)
	}
	return nil
}

// Close clears all in-memory entries.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*list.Element)
	s.evictList.Init()
	return nil
}
