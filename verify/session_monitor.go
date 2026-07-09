package verify

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// SessionMonitor manages periodic re-verification of long-lived connections.
// It periodically re-checks TL status and actively disconnects if revoked.
type SessionMonitor struct {
	interval    time.Duration
	tlogClient  TransparencyLogClient
	dnsResolver DNSResolver
	tlBaseURL   string
	onRevoked   func(fqdn string, err error)
	logger      *slog.Logger

	mu       sync.Mutex
	sessions map[string]*monitoredSession
	stopCh   chan struct{}
	stopped  bool
}

type monitoredSession struct {
	fqdn   models.Fqdn
	cert   *CertIdentity
	cancel context.CancelFunc
}

// NewSessionMonitor creates a monitor that periodically re-checks connections.
func NewSessionMonitor(interval time.Duration, tlogClient TransparencyLogClient, dnsResolver DNSResolver, onRevoked func(string, error)) *SessionMonitor {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &SessionMonitor{
		interval:    interval,
		tlogClient:  tlogClient,
		dnsResolver: dnsResolver,
		tlBaseURL:   defaultCNNICTLBaseURL,
		onRevoked:   onRevoked,
		logger:      slog.Default(),
		sessions:    make(map[string]*monitoredSession),
		stopCh:      make(chan struct{}),
	}
}

// Watch starts monitoring a connection. Returns a stop function.
func (m *SessionMonitor) Watch(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) (stop func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return func() {}
	}

	watchCtx, cancel := context.WithCancel(ctx)
	key := fqdn.String()

	session := &monitoredSession{
		fqdn:   fqdn,
		cert:   cert,
		cancel: cancel,
	}
	m.sessions[key] = session

	go m.monitorLoop(watchCtx, session)

	return func() {
		cancel()
		m.mu.Lock()
		delete(m.sessions, key)
		m.mu.Unlock()
	}
}

// Stop stops all monitoring goroutines.
func (m *SessionMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return
	}
	m.stopped = true
	close(m.stopCh)

	for _, s := range m.sessions {
		s.cancel()
	}
	m.sessions = make(map[string]*monitoredSession)
}

func (m *SessionMonitor) monitorLoop(ctx context.Context, session *monitoredSession) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.recheck(ctx, session); err != nil {
				if m.onRevoked != nil {
					m.onRevoked(session.fqdn.String(), err)
				}
				return
			}
		}
	}
}

func (m *SessionMonitor) recheck(ctx context.Context, session *monitoredSession) error {
	result, err := m.dnsResolver.LookupATIDiscovery(ctx, session.fqdn)
	if err != nil {
		m.logger.WarnContext(ctx, "session monitor: DNS lookup failed",
			slog.String("fqdn", session.fqdn.String()), slog.String("error", err.Error()))
		return nil
	}
	if !result.Found || len(result.Records) == 0 {
		return nil
	}

	agentID := result.Records[0].ID
	tlURL := m.tlBaseURL + "/tl/agents/" + agentID + "/logs/latest"

	tlResp, err := m.tlogClient.FetchTLResponse(ctx, tlURL)
	if err != nil {
		m.logger.WarnContext(ctx, "session monitor: TL fetch failed",
			slog.String("fqdn", session.fqdn.String()), slog.String("error", err.Error()))
		return nil
	}

	status := models.TLAgentStatus(strings.ToUpper(tlResp.Payload.AgentStatus))
	if status.IsTerminal() {
		return NewANSError(CodeRevokedDuringSession, SeverityHard, StageSession,
			"agent revoked/expired during session: "+string(status))
	}

	return nil
}
