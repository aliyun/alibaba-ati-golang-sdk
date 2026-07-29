package crl

// Status represents the result status of a CRL check.
type Status int

const (
	Skipped Status = iota // no CDP found, CRL check not applicable
	Passed                // certificate is not revoked
	Revoked               // certificate serial found in CRL
	Failed                // CRL check could not be completed (fetch/parse/verify error)
)

func (s Status) String() string {
	switch s {
	case Skipped:
		return "SKIPPED"
	case Passed:
		return "PASSED"
	case Revoked:
		return "REVOKED"
	case Failed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// Result holds the outcome of a CRL revocation check.
type Result struct {
	Status  Status
	Message string
	CDPURI  string
}

// ShouldReject returns true if the connection should be rejected based on this result.
func (r Result) ShouldReject() bool {
	return r.Status == Revoked
}
