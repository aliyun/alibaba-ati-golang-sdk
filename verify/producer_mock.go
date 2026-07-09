package verify

import (
	"crypto/ecdsa"
	"fmt"
)

// MockProducerKeyLookup is a test double for ProducerKeyLookup.
type MockProducerKeyLookup struct {
	keys map[string]*ecdsa.PublicKey
	err  error
}

// NewMockProducerKeyLookup creates a new mock producer key lookup.
func NewMockProducerKeyLookup() *MockProducerKeyLookup {
	return &MockProducerKeyLookup{keys: make(map[string]*ecdsa.PublicKey)}
}

// WithKey adds a key for the given kid.
func (m *MockProducerKeyLookup) WithKey(kid string, key *ecdsa.PublicKey) *MockProducerKeyLookup {
	m.keys[kid] = key
	return m
}

// WithError makes all lookups return an error.
func (m *MockProducerKeyLookup) WithError(err error) *MockProducerKeyLookup {
	m.err = err
	return m
}

// GetProducerKey implements ProducerKeyLookup.
func (m *MockProducerKeyLookup) GetProducerKey(kid string) (*ecdsa.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	key, ok := m.keys[kid]
	if !ok {
		return nil, fmt.Errorf("producer key %q not found", kid)
	}
	return key, nil
}
