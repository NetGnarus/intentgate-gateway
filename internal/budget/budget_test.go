package budget

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/capability"
)

// --- MemoryStore ----------------------------------------------------------

func TestMemoryStoreIncrementsFromOne(t *testing.T) {
	s := NewMemoryStore()
	for want := int64(1); want <= 5; want++ {
		got, err := s.Increment(context.Background(), "k", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("Increment #%d returned %d, want %d", want, got, want)
		}
	}
}

func TestMemoryStoreKeysAreIsolated(t *testing.T) {
	s := NewMemoryStore()
	if v, _ := s.Increment(context.Background(), "a", time.Hour); v != 1 {
		t.Errorf("a first call: %d", v)
	}
	if v, _ := s.Increment(context.Background(), "b", time.Hour); v != 1 {
		t.Errorf("b first call: %d", v)
	}
	if v, _ := s.Increment(context.Background(), "a", time.Hour); v != 2 {
		t.Errorf("a second call: %d", v)
	}
}

func TestMemoryStoreConcurrentSafety(t *testing.T) {
	s := NewMemoryStore()
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = s.Increment(context.Background(), "shared", time.Hour)
		}()
	}
	wg.Wait()
	v, _ := s.Increment(context.Background(), "shared", time.Hour)
	if v != int64(N+1) {
		t.Errorf("after %d concurrent increments + 1, got %d, want %d", N, v, N+1)
	}
}

func TestMemoryStoreTTLExpiry(t *testing.T) {
	s := NewMemoryStore()
	if v, _ := s.Increment(context.Background(), "k", 10*time.Millisecond); v != 1 {
		t.Errorf("first: %d", v)
	}
	if v, _ := s.Increment(context.Background(), "k", 10*time.Millisecond); v != 2 {
		t.Errorf("second: %d", v)
	}
	time.Sleep(20 * time.Millisecond)
	if v, _ := s.Increment(context.Background(), "k", 10*time.Millisecond); v != 1 {
		t.Errorf("after expiry: %d, want 1", v)
	}
}

// --- Check (the budget pipeline stage) ----------------------------------

func mustToken(t *testing.T, caveats ...capability.Caveat) *capability.Token {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	tok, err := capability.Mint(key, capability.MintOptions{
		Subject: "agent-x",
		Caveats: caveats,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCheckSkipsWhenNoCaveat(t *testing.T) {
	tok := mustToken(t) // no max_calls caveat
	d, err := Check(context.Background(), nil, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Errorf("expected allow, got %+v", d)
	}
	// store must not be required when no caveat exists
}

func TestCheckEnforcesSingleCaveat(t *testing.T) {
	tok := mustToken(t, capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 2})
	store := NewMemoryStore()

	for i := int64(1); i <= 2; i++ {
		d, err := Check(context.Background(), store, tok)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed {
			t.Errorf("call %d should allow, got %+v", i, d)
		}
		if d.Used != i {
			t.Errorf("call %d Used=%d", i, d.Used)
		}
	}
	// Third call must be denied.
	d, err := Check(context.Background(), store, tok)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Errorf("third call should deny, got %+v", d)
	}
	if d.Limit != 2 {
		t.Errorf("Limit=%d, want 2", d.Limit)
	}
	if d.Used != 3 {
		t.Errorf("Used=%d, want 3", d.Used)
	}
}

func TestCheckHonorsStrictestOfMultipleCaveats(t *testing.T) {
	// Two caveats: 5 and 2. The second is more restrictive — that's
	// the one that should fire on call #3.
	tok := mustToken(t,
		capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 5},
		capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 2},
	)
	store := NewMemoryStore()

	_, _ = Check(context.Background(), store, tok)
	_, _ = Check(context.Background(), store, tok)
	d, _ := Check(context.Background(), store, tok)
	if d.Allowed {
		t.Errorf("expected deny on third call")
	}
	if d.Limit != 2 {
		t.Errorf("Limit=%d, want 2 (the strictest)", d.Limit)
	}
}

func TestCheckErrorsWhenStoreNilButCaveatPresent(t *testing.T) {
	tok := mustToken(t, capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 1})
	_, err := Check(context.Background(), nil, tok)
	if err == nil {
		t.Fatalf("expected error: store is nil but token has max_calls")
	}
}

func TestCheckIgnoresZeroMaxCalls(t *testing.T) {
	// MaxCalls=0 means "no limit declared"; treat as no caveat.
	tok := mustToken(t, capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 0})
	d, err := Check(context.Background(), nil, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Fatalf("MaxCalls=0 should not enforce, got %+v", d)
	}
}

func TestCheckPerTokenIsolation(t *testing.T) {
	// Two distinct tokens with the same limit should not share counters.
	tokA := mustToken(t, capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 1})
	tokB := mustToken(t, capability.Caveat{Type: capability.CaveatMaxCalls, MaxCalls: 1})
	if tokA.ID == tokB.ID {
		t.Skip("token IDs collided; cannot test isolation")
	}
	store := NewMemoryStore()

	if d, _ := Check(context.Background(), store, tokA); !d.Allowed {
		t.Errorf("token A first call should allow")
	}
	if d, _ := Check(context.Background(), store, tokB); !d.Allowed {
		t.Errorf("token B first call should allow (separate counter)")
	}
}
