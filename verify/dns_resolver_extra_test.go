package verify

import (
	"net"
	"testing"
	"time"
)

// TestStandardDNSResolver_DefaultCacheTTL verifies that NewStandardDNSResolver
// sets the default cache TTL to 5 minutes.
func TestStandardDNSResolver_DefaultCacheTTL(t *testing.T) {
	r := NewStandardDNSResolver()
	if r.cacheTTL != defaultDNSCacheTTL {
		t.Errorf("cacheTTL = %v, want %v", r.cacheTTL, defaultDNSCacheTTL)
	}
	if r.cacheTTL != 5*time.Minute {
		t.Errorf("cacheTTL = %v, want 5m", r.cacheTTL)
	}
}

// TestStandardDNSResolver_WithCacheTTL verifies that WithCacheTTL sets a
// custom TTL value on the resolver.
func TestStandardDNSResolver_WithCacheTTL(t *testing.T) {
	r := NewStandardDNSResolver()
	customTTL := 30 * time.Second
	got := r.WithCacheTTL(customTTL)
	if got != r {
		t.Error("WithCacheTTL should return the same resolver for chaining")
	}
	if r.cacheTTL != customTTL {
		t.Errorf("cacheTTL = %v, want %v", r.cacheTTL, customTTL)
	}
}

// TestStandardDNSResolver_WithCacheTTL_ZeroDuration verifies that a zero
// TTL is stored as-is (no implicit clamping).
func TestStandardDNSResolver_WithCacheTTL_ZeroDuration(t *testing.T) {
	r := NewStandardDNSResolver()
	r.WithCacheTTL(0)
	if r.cacheTTL != 0 {
		t.Errorf("cacheTTL = %v, want 0", r.cacheTTL)
	}
}

// TestStandardDNSResolver_WithTimeout_Chaining verifies that WithTimeout
// returns the same resolver instance and updates the timeout field.
func TestStandardDNSResolver_WithTimeout_Chaining(t *testing.T) {
	r := NewStandardDNSResolver()
	original := r.timeout
	got := r.WithTimeout(3 * time.Second)
	if got != r {
		t.Error("WithTimeout should return the same resolver for chaining")
	}
	if r.timeout == original {
		t.Error("expected timeout to change after WithTimeout")
	}
	if r.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", r.timeout)
	}
}

// TestStandardDNSResolver_WithServerAddress_HostOnly_AddsPort53 verifies
// that a bare hostname gets a custom PreferGo resolver. The resolver
// should differ from the original system resolver.
func TestStandardDNSResolver_WithServerAddress_HostOnly_AddsPort53(t *testing.T) {
	r := NewStandardDNSResolver()
	original := r.resolver
	r.WithServerAddress("8.8.8.8")
	if r.resolver == original {
		t.Fatal("expected a new custom resolver to be set for host-only address")
	}
	if !r.resolver.PreferGo {
		t.Error("expected PreferGo=true on custom resolver")
	}
	if r.resolver.Dial == nil {
		t.Fatal("expected a custom Dial func")
	}
}

// TestStandardDNSResolver_WithServerAddress_HostPort_UsesAsIs verifies
// that a host:port address is used as-is, producing a custom resolver.
func TestStandardDNSResolver_WithServerAddress_HostPort_UsesAsIs(t *testing.T) {
	r := NewStandardDNSResolver()
	original := r.resolver
	r.WithServerAddress("1.1.1.1:5300")
	if r.resolver == original {
		t.Fatal("expected a new custom resolver to be set for host:port address")
	}
	if r.resolver.Dial == nil {
		t.Fatal("expected a custom Dial func")
	}
}

// TestStandardDNSResolver_WithResolver_SetsCustom verifies that
// WithResolver stores the provided *net.Resolver.
func TestStandardDNSResolver_WithResolver_SetsCustom(t *testing.T) {
	r := NewStandardDNSResolver()
	custom := &net.Resolver{PreferGo: true}
	got := r.WithResolver(custom)
	if got != r {
		t.Error("WithResolver should return the same resolver for chaining")
	}
	if r.resolver != custom {
		t.Error("expected custom resolver to be set")
	}
}

// TestStandardDNSResolver_CacheHit verifies that setCache followed by
// getCached returns the same value immediately.
func TestStandardDNSResolver_CacheHit(t *testing.T) {
	r := NewStandardDNSResolver().WithCacheTTL(5 * time.Minute)

	type testPayload struct {
		Name string
		Val  int
	}
	payload := &testPayload{Name: "agent", Val: 42}

	r.setCache("key-hit", payload)
	got, ok := r.getCached("key-hit")
	if !ok {
		t.Fatal("getCached() ok = false, want true")
	}
	result, ok := got.(*testPayload)
	if !ok {
		t.Fatalf("getCached() returned %T, want *testPayload", got)
	}
	if result.Name != "agent" || result.Val != 42 {
		t.Errorf("getCached() = %+v, want {agent 42}", result)
	}
}

// TestStandardDNSResolver_CacheMiss verifies that getCached returns false
// for a key that was never stored.
func TestStandardDNSResolver_CacheMiss(t *testing.T) {
	r := NewStandardDNSResolver().WithCacheTTL(5 * time.Minute)
	got, ok := r.getCached("nonexistent-key")
	if ok {
		t.Error("getCached() ok = true for missing key, want false")
	}
	if got != nil {
		t.Errorf("getCached() = %v, want nil for missing key", got)
	}
}

// TestStandardDNSResolver_CacheExpiry verifies that a cached entry
// becomes invisible after the TTL has elapsed.
func TestStandardDNSResolver_CacheExpiry(t *testing.T) {
	r := NewStandardDNSResolver().WithCacheTTL(1 * time.Millisecond)
	r.setCache("key-expired", "stale-value")

	// Wait for the TTL to expire.
	time.Sleep(5 * time.Millisecond)

	got, ok := r.getCached("key-expired")
	if ok {
		t.Error("getCached() ok = true for expired key, want false")
	}
	if got != nil {
		t.Errorf("getCached() = %v, want nil for expired key", got)
	}

	// The expired entry should also be deleted from the underlying map.
	if _, ok := r.cache.Load("key-expired"); ok {
		t.Error("expired entry should have been deleted from cache")
	}
}

// TestStandardDNSResolver_ClearCache verifies that ClearCache removes all
// entries from the cache.
func TestStandardDNSResolver_ClearCache(t *testing.T) {
	r := NewStandardDNSResolver().WithCacheTTL(5 * time.Minute)

	r.setCache("key-1", "value-1")
	r.setCache("key-2", "value-2")
	r.setCache("key-3", "value-3")

	// Verify entries exist.
	for _, key := range []string{"key-1", "key-2", "key-3"} {
		if _, ok := r.getCached(key); !ok {
			t.Fatalf("getCached(%q) ok = false before ClearCache, want true", key)
		}
	}

	r.ClearCache()

	// Verify all entries are gone.
	count := 0
	r.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("cache entry count after ClearCache = %d, want 0", count)
	}

	for _, key := range []string{"key-1", "key-2", "key-3"} {
		if _, ok := r.getCached(key); ok {
			t.Errorf("getCached(%q) ok = true after ClearCache, want false", key)
		}
	}
}

// TestStandardDNSResolver_ClearCache_Empty verifies that ClearCache on an
// empty cache is a no-op (no panic, no error).
func TestStandardDNSResolver_ClearCache_Empty(t *testing.T) {
	r := NewStandardDNSResolver()

	// Should not panic on empty cache.
	r.ClearCache()

	count := 0
	r.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("cache entry count = %d, want 0 after ClearCache on empty cache", count)
	}
}

// TestStandardDNSResolver_CacheOverwrite verifies that storing a value
// with an existing key overwrites the previous value.
func TestStandardDNSResolver_CacheOverwrite(t *testing.T) {
	r := NewStandardDNSResolver().WithCacheTTL(5 * time.Minute)

	r.setCache("key-overwrite", "first")
	r.setCache("key-overwrite", "second")

	got, ok := r.getCached("key-overwrite")
	if !ok {
		t.Fatal("getCached() ok = false, want true")
	}
	if got != "second" {
		t.Errorf("getCached() = %v, want %q (overwritten value)", got, "second")
	}
}
