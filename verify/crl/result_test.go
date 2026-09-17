package crl

import (
	"testing"
)

func TestStatus_String(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{Skipped, "SKIPPED"},
		{Passed, "PASSED"},
		{Revoked, "REVOKED"},
		{Failed, "FAILED"},
		{Status(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestResult_ShouldReject(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   bool
	}{
		{"revoked rejects", Result{Status: Revoked}, true},
		{"passed does not reject", Result{Status: Passed}, false},
		{"skipped does not reject", Result{Status: Skipped}, false},
		{"failed rejects (fail-closed per R6.3)", Result{Status: Failed}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ShouldReject(); got != tt.want {
				t.Errorf("ShouldReject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResult_Fields(t *testing.T) {
	r := Result{
		Status:  Passed,
		Message: "certificate not revoked",
		CDPURI:  "http://crl.example.com/root.crl",
	}
	if r.Status != Passed {
		t.Errorf("Status = %v, want Passed", r.Status)
	}
	if r.Message != "certificate not revoked" {
		t.Errorf("Message = %q", r.Message)
	}
	if r.CDPURI != "http://crl.example.com/root.crl" {
		t.Errorf("CDPURI = %q", r.CDPURI)
	}
}
