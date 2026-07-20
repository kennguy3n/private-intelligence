package privacy

import "testing"

func TestCheckManagedEncrypted(t *testing.T) {
	g := NewGuard()
	if err := g.Check("tenant1", "managed_encrypted"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckStrictZk(t *testing.T) {
	g := NewGuard()
	err := g.Check("tenant1", "strict_zk")
	if err != ErrStrictZkForbidden {
		t.Fatalf("expected ErrStrictZkForbidden, got %v", err)
	}
}

func TestCheckInvalidMode(t *testing.T) {
	g := NewGuard()
	err := g.Check("tenant1", "plaintext")
	if err != ErrInvalidFolderMode {
		t.Fatalf("expected ErrInvalidFolderMode, got %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	g := NewGuard()
	// Exhaust the limit (100 req/min)
	for i := 0; i < 100; i++ {
		if err := g.Check("tenant1", "managed_encrypted"); err != nil {
			t.Fatalf("unexpected error at req %d: %v", i, err)
		}
	}
	// 101st should fail
	err := g.Check("tenant1", "managed_encrypted")
	if err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestWipe(t *testing.T) {
	data := []byte("sensitive content")
	Wipe(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte at index %d is %d, expected 0", i, b)
		}
	}
}
