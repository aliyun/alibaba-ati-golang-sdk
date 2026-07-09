package verify

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestMockDNSResolver_LookupATIBadge_Found(t *testing.T) {
	fqdn, _ := models.NewFqdn("test.example.com")
	v := models.NewVersion(1, 0, 0)
	mock := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123", Version: &v},
		})

	result, err := mock.LookupATIBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIBadge() error = %v", err)
	}
	if !result.Found {
		t.Error("LookupATIBadge() Found = false, want true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("LookupATIBadge() Records length = %d, want 1", len(result.Records))
	}
	if result.Records[0].Source != BadgeRecordSourceATIBadge {
		t.Errorf("Source = %v, want BadgeRecordSourceATIBadge", result.Records[0].Source)
	}
}

func TestMockDNSResolver_LookupATIBadge_RaBadgeFallback(t *testing.T) {
	fqdn, _ := models.NewFqdn("test.example.com")
	mock := NewMockDNSResolver().
		WithRaBadgeRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/legacy"},
		})

	result, err := mock.LookupATIBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIBadge() error = %v", err)
	}
	if !result.Found {
		t.Error("LookupATIBadge() Found = false, want true")
	}
	if result.Records[0].Source != BadgeRecordSourceRaBadge {
		t.Errorf("Source = %v, want BadgeRecordSourceRaBadge", result.Records[0].Source)
	}
}

func TestMockDNSResolver_LookupATIBadge_NotFound(t *testing.T) {
	fqdn, _ := models.NewFqdn("unknown.example.com")
	mock := NewMockDNSResolver()

	result, err := mock.LookupATIBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIBadge() unexpected error = %v", err)
	}
	if result.Found {
		t.Error("LookupATIBadge() Found = true, want false")
	}
}

func TestMockDNSResolver_LookupATIBadge_Error(t *testing.T) {
	fqdn, _ := models.NewFqdn("error.example.com")
	mock := NewMockDNSResolver().
		WithError("error.example.com", errors.New("dns failure"))

	_, err := mock.LookupATIBadge(context.Background(), fqdn)
	if err == nil {
		t.Fatal("LookupATIBadge() expected error")
	}
}

func TestMockDNSResolver_FindBadgeForVersion(t *testing.T) {
	fqdn, _ := models.NewFqdn("test.example.com")
	v100 := models.NewVersion(1, 0, 0)
	v200 := models.NewVersion(2, 0, 0)

	tests := []struct {
		name         string
		records      []ATIBadgeRecord
		version      models.Version
		wantURL      string
		wantErr      bool
		wantNotFound bool
	}{
		{
			name: "exact version match",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/v1", Version: &v100},
				{URL: "https://tlog.example.com/v2", Version: &v200},
			},
			version: v100,
			wantURL: "https://tlog.example.com/v1",
		},
		{
			name: "versionless fallback",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/latest", Version: nil},
			},
			version: v100,
			wantURL: "https://tlog.example.com/latest",
		},
		{
			name: "no matching version",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/v2", Version: &v200},
			},
			version:      v100,
			wantNotFound: true,
		},
		{
			name:         "no records at all",
			records:      nil,
			version:      v100,
			wantNotFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockDNSResolver()
			if len(tt.records) > 0 {
				mock.WithRecords("test.example.com", tt.records)
			}

			record, err := mock.FindBadgeForVersion(context.Background(), fqdn, tt.version)
			if tt.wantNotFound {
				if !errors.Is(err, ErrRecordNotFound) {
					t.Errorf("FindBadgeForVersion() error = %v, want ErrRecordNotFound", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindBadgeForVersion() error = %v", err)
			}
			if record.URL != tt.wantURL {
				t.Errorf("FindBadgeForVersion() URL = %q, want %q", record.URL, tt.wantURL)
			}
		})
	}
}

func TestMockDNSResolver_FindBadgeForVersion_Error(t *testing.T) {
	fqdn, _ := models.NewFqdn("error.example.com")
	mock := NewMockDNSResolver().
		WithError("error.example.com", errors.New("dns failure"))

	_, err := mock.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(1, 0, 0))
	if err == nil {
		t.Fatal("FindBadgeForVersion() expected error")
	}
}

func TestMockDNSResolver_FindPreferredBadge(t *testing.T) {
	fqdn, _ := models.NewFqdn("test.example.com")
	v100 := models.NewVersion(1, 0, 0)
	v200 := models.NewVersion(2, 0, 0)
	v300 := models.NewVersion(3, 0, 0)

	tests := []struct {
		name    string
		records []ATIBadgeRecord
		wantURL string
		wantErr bool
	}{
		{
			name: "selects highest version",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/v1", Version: &v100},
				{URL: "https://tlog.example.com/v3", Version: &v300},
				{URL: "https://tlog.example.com/v2", Version: &v200},
			},
			wantURL: "https://tlog.example.com/v3",
		},
		{
			name: "versioned over nil",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/nil", Version: nil},
				{URL: "https://tlog.example.com/v1", Version: &v100},
			},
			wantURL: "https://tlog.example.com/v1",
		},
		{
			name: "nil only",
			records: []ATIBadgeRecord{
				{URL: "https://tlog.example.com/nil", Version: nil},
			},
			wantURL: "https://tlog.example.com/nil",
		},
		{
			name:    "no records",
			records: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockDNSResolver()
			if len(tt.records) > 0 {
				mock.WithRecords("test.example.com", tt.records)
			}

			record, err := mock.FindPreferredBadge(context.Background(), fqdn)
			if tt.wantErr {
				if !errors.Is(err, ErrRecordNotFound) {
					t.Errorf("FindPreferredBadge() error = %v, want ErrRecordNotFound", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindPreferredBadge() error = %v", err)
			}
			if record.URL != tt.wantURL {
				t.Errorf("FindPreferredBadge() URL = %q, want %q", record.URL, tt.wantURL)
			}
		})
	}
}

func TestMockDNSResolver_FindPreferredBadge_Error(t *testing.T) {
	fqdn, _ := models.NewFqdn("error.example.com")
	mock := NewMockDNSResolver().
		WithError("error.example.com", errors.New("dns failure"))

	_, err := mock.FindPreferredBadge(context.Background(), fqdn)
	if err == nil {
		t.Fatal("FindPreferredBadge() expected error")
	}
}

func TestMockDNSResolver_FindPreferredBadge_AllNilVersions(t *testing.T) {
	fqdn, _ := models.NewFqdn("test.example.com")
	mock := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/a", Version: nil},
			{URL: "https://tlog.example.com/b", Version: nil},
		})

	record, err := mock.FindPreferredBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("FindPreferredBadge() error = %v", err)
	}
	if record == nil {
		t.Fatal("FindPreferredBadge() returned nil")
	}
}

// ---------------------------------------------------------------------------
// StandardDNSResolver tests
// ---------------------------------------------------------------------------

func TestStandardDNSResolver_NewDefaults(t *testing.T) {
	r := NewStandardDNSResolver()
	if r.resolver == nil {
		t.Error("expected default resolver to be set")
	}
	if r.timeout != defaultDNSTimeoutSeconds*time.Second {
		t.Errorf("expected timeout %v, got %v", defaultDNSTimeoutSeconds*time.Second, r.timeout)
	}
}

func TestStandardDNSResolver_WithResolver_Custom(t *testing.T) {
	custom := &net.Resolver{PreferGo: true}
	r := NewStandardDNSResolver().WithResolver(custom)
	if r.resolver != custom {
		t.Error("expected custom resolver to be set")
	}
}

func TestStandardDNSResolver_WithTimeout_Custom(t *testing.T) {
	r := NewStandardDNSResolver().WithTimeout(42 * time.Second)
	if r.timeout != 42*time.Second {
		t.Errorf("expected timeout 42s, got %v", r.timeout)
	}
}

func TestStandardDNSResolver_WithServerAddress_Empty(t *testing.T) {
	// Empty address is a no-op: keeps the default (system) resolver.
	r := NewStandardDNSResolver()
	original := r.resolver
	got := r.WithServerAddress("")
	if got != r {
		t.Error("WithServerAddress should return the same resolver for chaining")
	}
	if r.resolver != original {
		t.Error("empty address should keep the system resolver unchanged")
	}
}

func TestStandardDNSResolver_WithServerAddress_HostOnly(t *testing.T) {
	// A bare host gets a custom PreferGo resolver dialing port 53.
	r := NewStandardDNSResolver()
	original := r.resolver
	r.WithServerAddress("1.2.3.4")
	if r.resolver == original {
		t.Fatal("expected a new custom resolver to be set")
	}
	if !r.resolver.PreferGo {
		t.Error("expected PreferGo=true on custom resolver")
	}
	if r.resolver.Dial == nil {
		t.Fatal("expected a custom Dial func")
	}
	// The Dial func should target 1.2.3.4:53. We can't observe the address
	// directly, but a dial to a black-holed context should fail fast rather
	// than hitting the system resolver.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _ = r.resolver.Dial(ctx, "udp", "ignored:53")
}

func TestStandardDNSResolver_WithServerAddress_HostPort(t *testing.T) {
	r := NewStandardDNSResolver()
	original := r.resolver
	r.WithServerAddress("8.8.8.8:5353")
	if r.resolver == original {
		t.Fatal("expected a new custom resolver to be set")
	}
	if r.resolver.Dial == nil {
		t.Fatal("expected a custom Dial func")
	}
}

func TestStandardDNSResolver_HandleLookupError_NonDNSError(t *testing.T) {
	r := NewStandardDNSResolver()
	_, err := r.handleLookupError(context.DeadlineExceeded, "_ati-badge.example.com")
	if err == nil {
		t.Fatal("expected error for non-DNS error")
	}
	var dnsErr *DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected *DNSError, got %T", err)
	}
	if dnsErr.Type != DNSErrorLookupFailed {
		t.Errorf("expected DNSErrorLookupFailed, got %v", dnsErr.Type)
	}
}

func TestStandardDNSResolver_HandleLookupError_NotFound(t *testing.T) {
	r := NewStandardDNSResolver()
	netErr := &net.DNSError{
		Err:        "no such host",
		Name:       "_ati-badge.example.com",
		IsNotFound: true,
	}
	result, err := r.handleLookupError(netErr, "_ati-badge.example.com")
	if err != nil {
		t.Fatalf("expected no error for not-found, got %v", err)
	}
	if result.Found {
		t.Error("expected Found=false for not-found error")
	}
}

func TestStandardDNSResolver_HandleLookupError_Timeout(t *testing.T) {
	r := NewStandardDNSResolver()
	netErr := &net.DNSError{
		Err:       "timeout",
		Name:      "_ati-badge.example.com",
		IsTimeout: true,
	}
	_, err := r.handleLookupError(netErr, "_ati-badge.example.com")
	if err == nil {
		t.Fatal("expected error for timeout")
	}
	var dnsErr *DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected *DNSError, got %T", err)
	}
	if dnsErr.Type != DNSErrorTimeout {
		t.Errorf("expected DNSErrorTimeout, got %v", dnsErr.Type)
	}
}

func TestStandardDNSResolver_HandleLookupError_GenericDNSError(t *testing.T) {
	r := NewStandardDNSResolver()
	netErr := &net.DNSError{
		Err:  "server misbehaving",
		Name: "_ati-badge.example.com",
	}
	_, err := r.handleLookupError(netErr, "_ati-badge.example.com")
	if err == nil {
		t.Fatal("expected error for generic DNS error")
	}
	var dnsErr *DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected *DNSError, got %T", err)
	}
	if dnsErr.Type != DNSErrorLookupFailed {
		t.Errorf("expected DNSErrorLookupFailed, got %v", dnsErr.Type)
	}
}

func TestStandardDNSResolver_LookupATIBadge_HardError(t *testing.T) {
	r := NewStandardDNSResolver().WithTimeout(1 * time.Second)
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:  "server misbehaving",
				Name: "test",
			}
		},
	}

	fqdn, _ := models.NewFqdn("error.example.com")
	_, err := r.LookupATIBadge(context.Background(), fqdn)
	if err == nil {
		t.Fatal("expected error for hard DNS failure")
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_LookupError(t *testing.T) {
	// When LookupATIBadge returns a non-DNSErrorNotFound error, FindBadgeForVersion should propagate it
	r := NewStandardDNSResolver().WithTimeout(1 * time.Second)
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:  "connection refused",
				Name: "test",
			}
		},
	}

	fqdn, _ := models.NewFqdn("norecords.example.com")
	version := models.NewVersion(1, 0, 0)

	_, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if err == nil {
		t.Fatal("expected error from FindBadgeForVersion")
	}
	// Should NOT be ErrRecordNotFound - it's a hard error
	if errors.Is(err, ErrRecordNotFound) {
		t.Error("should not be ErrRecordNotFound for DNS lookup error")
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_HardError(t *testing.T) {
	r := NewStandardDNSResolver().WithTimeout(1 * time.Second)
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:  "server misbehaving",
				Name: "test",
			}
		},
	}

	fqdn, _ := models.NewFqdn("error.example.com")
	version := models.NewVersion(1, 0, 0)

	_, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if err == nil {
		t.Fatal("expected error for hard DNS failure")
	}
	if errors.Is(err, ErrRecordNotFound) {
		t.Error("should not be ErrRecordNotFound for hard errors")
	}
}

func TestStandardDNSResolver_FindPreferredBadge_LookupError(t *testing.T) {
	r := NewStandardDNSResolver().WithTimeout(1 * time.Second)
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:  "connection refused",
				Name: "test",
			}
		},
	}

	fqdn, _ := models.NewFqdn("norecords.example.com")
	_, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err == nil {
		t.Fatal("expected error from FindPreferredBadge")
	}
	if errors.Is(err, ErrRecordNotFound) {
		t.Error("should not be ErrRecordNotFound for DNS lookup error")
	}
}

func TestStandardDNSResolver_FindPreferredBadge_HardError(t *testing.T) {
	r := NewStandardDNSResolver().WithTimeout(1 * time.Second)
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:  "server misbehaving",
				Name: "test",
			}
		},
	}

	fqdn, _ := models.NewFqdn("error.example.com")
	_, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err == nil {
		t.Fatal("expected error for hard DNS failure")
	}
	if errors.Is(err, ErrRecordNotFound) {
		t.Error("should not be ErrRecordNotFound for hard errors")
	}
}

func TestIsNotFoundError_Extended(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "DNSError with NotFound type",
			err:  &DNSError{Type: DNSErrorNotFound, Fqdn: "test.com"},
			want: true,
		},
		{
			name: "DNSError with LookupFailed type",
			err:  &DNSError{Type: DNSErrorLookupFailed, Fqdn: "test.com"},
			want: false,
		},
		{
			name: "DNSError with Timeout type",
			err:  &DNSError{Type: DNSErrorTimeout, Fqdn: "test.com"},
			want: false,
		},
		{
			name: "non-DNSError",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNotFoundError(tt.err)
			if got != tt.want {
				t.Errorf("isNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrRecordNotFound(t *testing.T) {
	if ErrRecordNotFound == nil {
		t.Fatal("ErrRecordNotFound should not be nil")
	}
	if ErrRecordNotFound.Error() != "no matching badge record found" {
		t.Errorf("unexpected error message: %s", ErrRecordNotFound.Error())
	}
}
