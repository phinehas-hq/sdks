package phinehas_test

import (
	"testing"
	"time"

	"github.com/phinehas-hq/sdks/packages/go/store"
)

func TestMemoryStoreLRUAndEviction(t *testing.T) {
	s := store.NewMemoryStore(3, time.Hour)

	_ = s.Ban("1.1.1.1", time.Hour)
	_ = s.Ban("2.2.2.2", time.Hour)
	_ = s.Ban("3.3.3.3", time.Hour)

	if s.Size() != 3 {
		t.Fatalf("Expected size 3, got %d", s.Size())
	}

	banned, _ := s.IsBanned("1.1.1.1")
	if !banned {
		t.Errorf("Expected 1.1.1.1 to be banned")
	}

	// Access 1.1.1.1 to move to front (MRU), making 2.2.2.2 LRU
	_, _ = s.IsBanned("1.1.1.1")

	// Add 4th -> evicts 2.2.2.2
	_ = s.Ban("4.4.4.4", time.Hour)
	if s.Size() != 3 {
		t.Fatalf("Expected size 3, got %d", s.Size())
	}

	banned2, _ := s.IsBanned("2.2.2.2")
	if banned2 {
		t.Errorf("Expected 2.2.2.2 to be evicted")
	}

	banned4, _ := s.IsBanned("4.4.4.4")
	if !banned4 {
		t.Errorf("Expected 4.4.4.4 to be banned")
	}

	_ = s.Unban("4.4.4.4")
	banned4After, _ := s.IsBanned("4.4.4.4")
	if banned4After {
		t.Errorf("Expected 4.4.4.4 to be unbanned")
	}

	_ = s.Close()
	if s.Size() != 0 {
		t.Errorf("Expected size 0 after close, got %d", s.Size())
	}
}

func TestMemoryStoreTTLExpiration(t *testing.T) {
	s := store.NewMemoryStore(10, 50*time.Millisecond)

	_ = s.Ban("10.0.0.1", 50*time.Millisecond)
	banned, _ := s.IsBanned("10.0.0.1")
	if !banned {
		t.Errorf("Expected 10.0.0.1 to be banned initially")
	}

	time.Sleep(70 * time.Millisecond)

	bannedAfter, _ := s.IsBanned("10.0.0.1")
	if bannedAfter {
		t.Errorf("Expected 10.0.0.1 to be expired")
	}

	// Permanent ban (ttl: 0)
	_ = s.Ban("10.0.0.2", 0)
	bannedPerm, _ := s.IsBanned("10.0.0.2")
	if !bannedPerm {
		t.Errorf("Expected 10.0.0.2 to be permanently banned")
	}
}
