package models

import "testing"

// TestIsValidRevocationReason_AllValidConstants supplements the existing
// revocation_test.go by covering every RevocationReason constant, including
// those omitted from the original test (ExpiredCert, RemoveFromCRL).
func TestIsValidRevocationReason_AllValidConstants(t *testing.T) {
	validReasons := []struct {
		name   string
		reason RevocationReason
	}{
		{"AA_COMPROMISE", RevocationReasonAACompromise},
		{"AFFILIATION_CHANGED", RevocationReasonAffiliationChanged},
		{"CA_COMPROMISE", RevocationReasonCACompromise},
		{"CERTIFICATE_HOLD", RevocationReasonCertificateHold},
		{"CESSATION_OF_OPERATION", RevocationReasonCessationOfOperation},
		{"EXPIRED_CERT", RevocationReasonExpiredCert},
		{"KEY_COMPROMISE", RevocationReasonKeyCompromise},
		{"PRIVILEGE_WITHDRAWN", RevocationReasonPrivilegeWithdrawn},
		{"REMOVE_FROM_CRL", RevocationReasonRemoveFromCRL},
		{"SUPERSEDED", RevocationReasonSuperseded},
		{"UNSPECIFIED", RevocationReasonUnspecified},
	}

	for _, tt := range validReasons {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidRevocationReason(tt.reason); !got {
				t.Errorf("IsValidRevocationReason(%q) = false, want true", tt.reason)
			}
		})
	}
}

// TestIsValidRevocationReason_InvalidValues supplements the existing
// revocation_test.go with additional invalid edge cases.
func TestIsValidRevocationReason_InvalidValues(t *testing.T) {
	invalidReasons := []struct {
		name   string
		reason RevocationReason
	}{
		{"empty string", RevocationReason("")},
		{"random string", RevocationReason("INVALID_REASON")},
		{"lowercase key compromise", RevocationReason("key_compromise")},
		{"unspecified lowercase", RevocationReason("unspecified")},
		{"numeric string", RevocationReason("999")},
		{"partially matching", RevocationReason("KEY_COMPROMISE_EXTRA")},
		{"whitespace", RevocationReason(" ")},
		{"key with spaces", RevocationReason("KEY COMPROMISE")},
		{"unspecified with trailing space", RevocationReason("UNSPECIFIED ")},
		{"arbitrary enum", RevocationReason("UNKNOWN")},
	}

	for _, tt := range invalidReasons {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidRevocationReason(tt.reason); got {
				t.Errorf("IsValidRevocationReason(%q) = true, want false", tt.reason)
			}
		})
	}
}

// TestIsValidRevocationReason_StringValues checks that each valid reason
// constant has the expected string representation.
func TestIsValidRevocationReason_StringValues(t *testing.T) {
	expected := map[RevocationReason]string{
		RevocationReasonAACompromise:         "AA_COMPROMISE",
		RevocationReasonAffiliationChanged:   "AFFILIATION_CHANGED",
		RevocationReasonCACompromise:         "CA_COMPROMISE",
		RevocationReasonCertificateHold:      "CERTIFICATE_HOLD",
		RevocationReasonCessationOfOperation: "CESSATION_OF_OPERATION",
		RevocationReasonExpiredCert:          "EXPIRED_CERT",
		RevocationReasonKeyCompromise:        "KEY_COMPROMISE",
		RevocationReasonPrivilegeWithdrawn:   "PRIVILEGE_WITHDRAWN",
		RevocationReasonRemoveFromCRL:        "REMOVE_FROM_CRL",
		RevocationReasonSuperseded:           "SUPERSEDED",
		RevocationReasonUnspecified:          "UNSPECIFIED",
	}

	for reason, want := range expected {
		if string(reason) != want {
			t.Errorf("RevocationReason string = %q, want %q", string(reason), want)
		}
		if !IsValidRevocationReason(reason) {
			t.Errorf("IsValidRevocationReason(%q) = false, want true", reason)
		}
	}
}
