package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Session struct {
	ID          string
	Initialized bool
	CreatedAt   time.Time
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
	go s.evictLoop()
	return s
}

func (s *SessionStore) Create() *Session {
	b := make([]byte, 16)
	rand.Read(b)
	sess := &Session{
		ID:        hex.EncodeToString(b),
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

func (s *SessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *SessionStore) evictLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, sess := range s.sessions {
			if now.Sub(sess.CreatedAt) > s.ttl {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}
