package models

import "encoding/json"

// TLResponse is the top-level response from the CNNIC Transparency Log query endpoint.
// Structure: status + schemaVersion + payload + evidenceRef + seal + merkleProof.
type TLResponse struct {
	Status        string      `json:"status"`
	SchemaVersion string      `json:"schemaVersion"`
	Payload       TLPayload   `json:"payload"`
	EvidenceRef   EvidenceRef `json:"evidenceRef"`
	Seal          TLSeal      `json:"seal"`
	MerkleProof   MerkleProof `json:"merkleProof"`
	RequestID     string      `json:"requestId"`

	// Raw JSON of the four sealed fields, preserved during deserialization
	// for exact seal signature verification. Nil when constructed via struct literal.
	RawStatus        json.RawMessage `json:"-"`
	RawSchemaVersion json.RawMessage `json:"-"`
	RawPayload       json.RawMessage `json:"-"`
	RawEvidenceRef   json.RawMessage `json:"-"`
}

func (r *TLResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r.RawStatus = raw["status"]
	r.RawSchemaVersion = raw["schemaVersion"]
	r.RawPayload = raw["payload"]
	r.RawEvidenceRef = raw["evidenceRef"]

	if v := raw["status"]; v != nil {
		json.Unmarshal(v, &r.Status)
	}
	if v := raw["schemaVersion"]; v != nil {
		json.Unmarshal(v, &r.SchemaVersion)
	}
	if v := raw["payload"]; v != nil {
		json.Unmarshal(v, &r.Payload)
	}
	if v := raw["evidenceRef"]; v != nil {
		json.Unmarshal(v, &r.EvidenceRef)
	}
	if v := raw["seal"]; v != nil {
		json.Unmarshal(v, &r.Seal)
	}
	if v := raw["merkleProof"]; v != nil {
		json.Unmarshal(v, &r.MerkleProof)
	}
	if v := raw["requestId"]; v != nil {
		json.Unmarshal(v, &r.RequestID)
	}
	return nil
}

// TLPayload is the core agent event data sealed in the TL.
type TLPayload struct {
	LogID            string         `json:"logId"`
	EventType        string         `json:"eventType"`
	Timestamp        string         `json:"timestamp"`
	AgentName        string         `json:"agentName"`
	AgentDisplayName string         `json:"agentDisplayName"`
	AgentHost        string         `json:"agentHost"`
	Version          string         `json:"version"`
	AgentID          string         `json:"agentId"`
	AgentStatus      string         `json:"agentStatus"`
	Certificates     TLCertificates `json:"certificates"`
}

// TLCertificates holds certificate fingerprints attested in the TL.
type TLCertificates struct {
	ServerCertFingerprint   string `json:"serverCertFingerprint"`
	IdentityCertFingerprint string `json:"identityCertFingerprint"`
}

// EvidenceRef is the evidence reference metadata from the RA submission.
type EvidenceRef struct {
	EvidenceID            string `json:"evidenceId"`
	SubmitterID           string `json:"submitterId"`
	EvidenceType          string `json:"evidenceType"`
	EvidenceURI           string `json:"evidenceUri"`
	EvidenceHash          string `json:"evidenceHash"`
	HashAlgorithm         string `json:"hashAlgorithm"`
	HashTarget            string `json:"hashTarget"`
	ContentType           string `json:"contentType"`
	EvidenceSchemaVersion string `json:"evidenceSchemaVersion"`
	SignatureRequired     bool   `json:"signatureRequired"`
}

// TLSeal is the TL's cryptographic seal over {status, schemaVersion, payload, evidenceRef}.
// Verification: JCS-canonicalize the sealed fields → SHA-256 → ECDSA P-256.
type TLSeal struct {
	Canonicalization   string `json:"canonicalization"`
	DigestAlgorithm    string `json:"digestAlgorithm"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	SignatureEncoding  string `json:"signatureEncoding"`
	KeyID              string `json:"keyId"`
	Signature          string `json:"signature"`
	PublicKey          string `json:"publicKey"`
}

// IdentityCertFingerprint returns the identity certificate fingerprint.
func (p *TLPayload) IdentityCertFingerprint() string {
	return p.Certificates.IdentityCertFingerprint
}

// ServerCertFingerprint returns the server certificate fingerprint.
func (p *TLPayload) ServerCertFingerprint() string {
	return p.Certificates.ServerCertFingerprint
}

// TLAgentStatus represents the status of an agent in the transparency log.
type TLAgentStatus string

const (
	TLStatusActive     TLAgentStatus = "ACTIVE"
	TLStatusWarning    TLAgentStatus = "WARNING"
	TLStatusDeprecated TLAgentStatus = "DEPRECATED"
	TLStatusExpired    TLAgentStatus = "EXPIRED"
	TLStatusRevoked    TLAgentStatus = "REVOKED"
)

// IsValidForConnection returns true if this status allows establishing a connection.
func (s TLAgentStatus) IsValidForConnection() bool {
	switch s {
	case TLStatusActive, TLStatusWarning, TLStatusDeprecated:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if this status permanently rejects connections.
func (s TLAgentStatus) IsTerminal() bool {
	return s == TLStatusRevoked || s == TLStatusExpired
}

// ShouldReject returns true if this status indicates the agent should be rejected.
func (s TLAgentStatus) ShouldReject() bool {
	return s == TLStatusExpired || s == TLStatusRevoked
}

// IsActive returns true if this status indicates the agent is fully active.
func (s TLAgentStatus) IsActive() bool {
	return s == TLStatusActive || s == TLStatusWarning
}
