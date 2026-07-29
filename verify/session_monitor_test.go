package verify

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func mustNewFqdn(t *testing.T, domain string) models.Fqdn {
	t.Helper()
	fqdn, err := models.NewFqdn(domain)
	if err != nil {
		t.Fatalf("NewFqdn(%q) error = %v", domain, err)
	}
	return fqdn
}

func makeTestFingerprint() CertFingerprint {
	var b [32]byte
	for i := range b {
		b[i] = byte(i + 1)
	}
	return CertFingerprintFromBytes(b)
}

func TestNewSessionMonitor_DefaultInterval(t *testing.T) {
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()

	m := NewSessionMonitor(0, tlogMock, dnsMock, nil)
	if m.interval != 5*time.Minute {
		t.Errorf("interval = %v, want %v", m.interval, 5*time.Minute)
	}

	m2 := NewSessionMonitor(-1, tlogMock, dnsMock, nil)
	if m2.interval != 5*time.Minute {
		t.Errorf("interval = %v, want %v", m2.interval, 5*time.Minute)
	}
}

func TestNewSessionMonitor_CustomInterval(t *testing.T) {
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()

	custom := 100 * time.Millisecond
	m := NewSessionMonitor(custom, tlogMock, dnsMock, nil)
	if m.interval != custom {
		t.Errorf("interval = %v, want %v", m.interval, custom)
	}
}

func TestSessionMonitor_WatchOnStoppedMonitor_Noop(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, nil)
	m.Stop()

	// Watch on stopped monitor should return a no-op stop function.
	stop := m.Watch(context.Background(), fqdn, cert)
	if stop == nil {
		t.Fatal("Watch() returned nil stop function")
	}
	// Calling the stop function should not panic.
	stop()
}

func TestSessionMonitor_Stop_CancelsAllSessions(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, nil)

	stop1 := m.Watch(context.Background(), fqdn, cert)
	stop2 := m.Watch(context.Background(), fqdn, cert)

	m.Stop()

	// After Stop, sessions map is cleared and stopped flag is true
	m.mu.Lock()
	if !m.stopped {
		t.Error("stopped flag not set")
	}
	if len(m.sessions) != 0 {
		t.Errorf("sessions not cleared, len = %d", len(m.sessions))
	}
	m.mu.Unlock()

	// Calling the stop functions should not panic
	stop1()
	stop2()

	// Calling Stop again should not panic (idempotent)
	m.Stop()
}

func TestSessionMonitor_WatchAndStopFunction_RemovesSession(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, nil)

	_ = m.Watch(context.Background(), fqdn, cert)

	// Verify session was added
	m.mu.Lock()
	if len(m.sessions) != 1 {
		m.mu.Unlock()
		t.Fatalf("expected 1 session, got %d", len(m.sessions))
	}
	m.mu.Unlock()

	// Watch again to get a stop function we can call
	stop := m.Watch(context.Background(), fqdn, cert)
	m.mu.Lock()
	if len(m.sessions) != 1 {
		m.mu.Unlock()
		t.Fatalf("expected 1 session (overwritten), got %d", len(m.sessions))
	}
	m.mu.Unlock()

	// Stop that session
	stop()

	m.mu.Lock()
	if len(m.sessions) != 0 {
		m.mu.Unlock()
		t.Errorf("expected 0 sessions after stop, got %d", len(m.sessions))
	} else {
		m.mu.Unlock()
	}

	m.Stop()
}

func TestSessionMonitor_Recheck_TerminalStatus_TriggersCallback(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	// Configure the TL response that recheck will fetch.
	// The URL pattern is: tlBaseURL + "/tl/agents/" + agentID + "/logs/latest"
	expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-123/logs/latest"
	tlogMock.WithTLResponse(expectedURL, &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusRevoked),
		},
	})

	var callbackFired int32
	var wg sync.WaitGroup
	wg.Add(1)

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
		wg.Done()
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	// Wait for the callback to fire (with timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for onRevoked callback")
	}

	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 1 {
		t.Error("onRevoked callback was not fired")
	}
}

func TestSessionMonitor_Recheck_TerminalStatus_Expired(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-456", "https://card.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-456/logs/latest"
	tlogMock.WithTLResponse(expectedURL, &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusExpired),
		},
	})

	var callbackFired int32
	var wg sync.WaitGroup
	wg.Add(1)

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
		wg.Done()
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for onRevoked callback for EXPIRED status")
	}

	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 1 {
		t.Error("onRevoked callback was not fired for EXPIRED status")
	}
}

func TestSessionMonitor_Recheck_ActiveStatus_NoCallback(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-123/logs/latest"
	tlogMock.WithTLResponse(expectedURL, &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
		},
	})

	var callbackFired int32

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	// Wait long enough for at least one recheck tick to fire
	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 0 {
		t.Error("onRevoked callback should NOT fire for ACTIVE status")
	}
}

func TestSessionMonitor_Recheck_DNSLookupFailure_NonFatal(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithError("agent.example.com", errors.New("DNS lookup failed"))
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	var callbackFired int32

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	// Wait long enough for at least one recheck tick to fire
	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 0 {
		t.Error("onRevoked callback should NOT fire on DNS lookup failure")
	}
}

func TestSessionMonitor_Recheck_TLFetchFailure_NonFatal(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	// Configure TL client to return an error for the expected URL
	expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-123/logs/latest"
	tlogMock.WithError(expectedURL, errors.New("TL fetch failed"))

	var callbackFired int32

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	// Wait long enough for at least one recheck tick to fire
	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 0 {
		t.Error("onRevoked callback should NOT fire on TL fetch failure")
	}
}

func TestSessionMonitor_Recheck_DNSNotFound_NonFatal(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	// DNS mock with no records configured => Found=false
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	var callbackFired int32

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
	})

	_ = m.Watch(context.Background(), fqdn, cert)

	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 0 {
		t.Error("onRevoked callback should NOT fire when DNS records not found")
	}
}

func TestSessionMonitor_Recheck_NoOnRevokedCallback(t *testing.T) {
	fqdn := mustNewFqdn(t, "agent.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()
	cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

	expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-123/logs/latest"
	tlogMock.WithTLResponse(expectedURL, &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusRevoked),
		},
	})

	// nil onRevoked callback — should not panic
	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, nil)

	_ = m.Watch(context.Background(), fqdn, cert)

	// Wait long enough for at least one recheck tick
	time.Sleep(200 * time.Millisecond)
	m.Stop()
	// If we reach here without panic, the test passes.
}

func TestSessionMonitor_StopIdempotent(t *testing.T) {
	dnsMock := NewMockDNSResolver()
	tlogMock := NewMockTransparencyLogClient()

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, nil)

	// Stop multiple times — should not panic
	m.Stop()
	m.Stop()
	m.Stop()
}

func TestSessionMonitor_WatchMultipleFqdns(t *testing.T) {
	fqdn1 := mustNewFqdn(t, "agent1.example.com")
	fqdn2 := mustNewFqdn(t, "agent2.example.com")
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent1.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-1", "https://card1.example.com/card.json"),
		}).
		WithDiscoveryRecords("agent2.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-2", "https://card2.example.com/card.json"),
		})
	tlogMock := NewMockTransparencyLogClient()

	cert1 := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent1.example.com")
	cert2 := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent2.example.com")

	expectedURL1 := defaultCNNICTLBaseURL + "/tl/agents/agent-1/logs/latest"
	expectedURL2 := defaultCNNICTLBaseURL + "/tl/agents/agent-2/logs/latest"
	tlogMock.WithTLResponse(expectedURL1, &models.TLResponse{
		Payload: models.TLPayload{AgentStatus: string(models.TLStatusActive)},
	})
	tlogMock.WithTLResponse(expectedURL2, &models.TLResponse{
		Payload: models.TLPayload{AgentStatus: string(models.TLStatusActive)},
	})

	var callbackFired int32

	m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
		atomic.StoreInt32(&callbackFired, 1)
	})

	_ = m.Watch(context.Background(), fqdn1, cert1)
	_ = m.Watch(context.Background(), fqdn2, cert2)

	m.mu.Lock()
	if len(m.sessions) != 2 {
		m.mu.Unlock()
		t.Errorf("expected 2 sessions, got %d", len(m.sessions))
	} else {
		m.mu.Unlock()
	}

	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if atomic.LoadInt32(&callbackFired) != 0 {
		t.Error("onRevoked callback should NOT fire for ACTIVE status")
	}
}

func TestSessionMonitor_Recheck_ActiveAndWarning_NoCallback(t *testing.T) {
	for _, status := range []models.TLAgentStatus{models.TLStatusActive, models.TLStatusWarning, models.TLStatusDeprecated} {
		t.Run(string(status), func(t *testing.T) {
			fqdn := mustNewFqdn(t, "agent.example.com")
			dnsMock := NewMockDNSResolver().
				WithDiscoveryRecords("agent.example.com", []*ATIRecord{
					makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
				})
			tlogMock := NewMockTransparencyLogClient()
			cert := CertIdentityFromFingerprintAndCN(makeTestFingerprint(), "agent.example.com")

			expectedURL := defaultCNNICTLBaseURL + "/tl/agents/agent-123/logs/latest"
			tlogMock.WithTLResponse(expectedURL, &models.TLResponse{
				Payload: models.TLPayload{AgentStatus: string(status)},
			})

			var callbackFired int32
			m := NewSessionMonitor(50*time.Millisecond, tlogMock, dnsMock, func(fqdn string, err error) {
				atomic.StoreInt32(&callbackFired, 1)
			})

			_ = m.Watch(context.Background(), fqdn, cert)
			time.Sleep(200 * time.Millisecond)
			m.Stop()

			if atomic.LoadInt32(&callbackFired) != 0 {
				t.Errorf("onRevoked callback should NOT fire for %s status", status)
			}
		})
	}
}
