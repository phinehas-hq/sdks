package store

import "time"

// BanStore specifies the contract for storage drivers tracking banned IP addresses.
type BanStore interface {
	// IsBanned checks whether an IP address is actively banned.
	IsBanned(ip string) (bool, error)

	// Ban registers an IP ban with the specified duration.
	// A TTL <= 0 denotes a permanent ban.
	Ban(ip string, ttl time.Duration) error

	// Unban removes an IP address from the ban store.
	Unban(ip string) error

	// Close cleans up store resources.
	Close() error
}
