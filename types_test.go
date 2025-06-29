package njalla

import (
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestNjallaRecordToLibdns_ARecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "A",
		Name:    "test",
		Content: "192.0.2.1",
		TTL:     3600,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	addr, ok := result.(libdns.Address)
	if !ok {
		t.Fatalf("Expected libdns.Address, got %T", result)
	}

	if addr.Name != "test" {
		t.Errorf("Expected name 'test', got %s", addr.Name)
	}

	if addr.TTL != time.Hour {
		t.Errorf("Expected TTL 1h, got %v", addr.TTL)
	}

	expectedIP := netip.MustParseAddr("192.0.2.1")
	if addr.IP != expectedIP {
		t.Errorf("Expected IP %v, got %v", expectedIP, addr.IP)
	}

	pd, ok := addr.ProviderData.(map[string]string)
	if !ok {
		t.Fatal("Expected ProviderData to be map[string]string")
	}

	if pd["id"] != "test-id" {
		t.Errorf("Expected ID 'test-id', got %s", pd["id"])
	}
}

func TestNjallaRecordToLibdns_AAAARecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "AAAA",
		Name:    "test",
		Content: "2001:db8::1",
		TTL:     3600,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	addr, ok := result.(libdns.Address)
	if !ok {
		t.Fatalf("Expected libdns.Address, got %T", result)
	}

	expectedIP := netip.MustParseAddr("2001:db8::1")
	if addr.IP != expectedIP {
		t.Errorf("Expected IP %v, got %v", expectedIP, addr.IP)
	}
}

func TestNjallaRecordToLibdns_CNAMERecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "CNAME",
		Name:    "www",
		Content: "example.com",
		TTL:     1800,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	cname, ok := result.(libdns.CNAME)
	if !ok {
		t.Fatalf("Expected libdns.CNAME, got %T", result)
	}

	if cname.Name != "www" {
		t.Errorf("Expected name 'www', got %s", cname.Name)
	}

	if cname.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got %s", cname.Target)
	}

	if cname.TTL != 30*time.Minute {
		t.Errorf("Expected TTL 30m, got %v", cname.TTL)
	}

	pd, ok := cname.ProviderData.(map[string]string)
	if !ok {
		t.Fatal("Expected ProviderData to be map[string]string")
	}

	if pd["id"] != "test-id" {
		t.Errorf("Expected ID 'test-id', got %s", pd["id"])
	}
}

func TestNjallaRecordToLibdns_TXTRecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "TXT",
		Name:    "_dmarc",
		Content: "v=DMARC1; p=none",
		TTL:     7200,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	txt, ok := result.(libdns.TXT)
	if !ok {
		t.Fatalf("Expected libdns.TXT, got %T", result)
	}

	if txt.Name != "_dmarc" {
		t.Errorf("Expected name '_dmarc', got %s", txt.Name)
	}

	if txt.Text != "v=DMARC1; p=none" {
		t.Errorf("Expected text 'v=DMARC1; p=none', got %s", txt.Text)
	}

	if txt.TTL != 2*time.Hour {
		t.Errorf("Expected TTL 2h, got %v", txt.TTL)
	}
}

func TestNjallaRecordToLibdns_MXRecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "MX",
		Name:    "@",
		Content: "mail.example.com",
		TTL:     3600,
		Prio:    10,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	mx, ok := result.(libdns.MX)
	if !ok {
		t.Fatalf("Expected libdns.MX, got %T", result)
	}

	if mx.Name != "@" {
		t.Errorf("Expected name '@', got %s", mx.Name)
	}

	if mx.Target != "mail.example.com" {
		t.Errorf("Expected target 'mail.example.com', got %s", mx.Target)
	}

	if mx.Preference != 10 {
		t.Errorf("Expected preference 10, got %d", mx.Preference)
	}

	if mx.TTL != time.Hour {
		t.Errorf("Expected TTL 1h, got %v", mx.TTL)
	}
}

func TestNjallaRecordToLibdns_SRVRecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "SRV",
		Name:    "_sip._tcp",
		Content: "sip.example.com",
		TTL:     3600,
		Prio:    10,
		Weight:  20,
		Port:    5060,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv, ok := result.(libdns.SRV)
	if !ok {
		t.Fatalf("Expected libdns.SRV, got %T", result)
	}

	if srv.Name != "_sip._tcp" {
		t.Errorf("Expected name '_sip._tcp', got %s", srv.Name)
	}

	if srv.Target != "sip.example.com" {
		t.Errorf("Expected target 'sip.example.com', got %s", srv.Target)
	}

	if srv.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", srv.Priority)
	}

	if srv.Weight != 20 {
		t.Errorf("Expected weight 20, got %d", srv.Weight)
	}

	if srv.Port != 5060 {
		t.Errorf("Expected port 5060, got %d", srv.Port)
	}
}

func TestNjallaRecordToLibdns_GenericRecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "NS",
		Name:    "@",
		Content: "ns1.example.com",
		TTL:     86400,
	}

	result, err := njallaRecordToLibdns(record)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	rr, ok := result.(libdns.RR)
	if !ok {
		t.Fatalf("Expected libdns.RR, got %T", result)
	}

	if rr.Name != "@" {
		t.Errorf("Expected name '@', got %s", rr.Name)
	}

	if rr.Type != "NS" {
		t.Errorf("Expected type 'NS', got %s", rr.Type)
	}

	if rr.Data != "ns1.example.com" {
		t.Errorf("Expected data 'ns1.example.com', got %s", rr.Data)
	}

	if rr.TTL != 24*time.Hour {
		t.Errorf("Expected TTL 24h, got %v", rr.TTL)
	}
}

func TestNjallaRecordToLibdns_InvalidARecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "A",
		Name:    "test",
		Content: "invalid-ip",
		TTL:     3600,
	}

	_, err := njallaRecordToLibdns(record)
	if err == nil {
		t.Fatal("Expected error for invalid A record IP")
	}

	expectedMsg := "invalid A record IP address"
	if !containsString(err.Error(), expectedMsg) {
		t.Errorf("Expected error to contain %q, got %q", expectedMsg, err.Error())
	}
}

func TestNjallaRecordToLibdns_InvalidAAAARecord(t *testing.T) {
	record := njallaRecord{
		ID:      "test-id",
		Domain:  "example.com",
		Type:    "AAAA",
		Name:    "test",
		Content: "invalid-ipv6",
		TTL:     3600,
	}

	_, err := njallaRecordToLibdns(record)
	if err == nil {
		t.Fatal("Expected error for invalid AAAA record IP")
	}

	expectedMsg := "invalid AAAA record IP address"
	if !containsString(err.Error(), expectedMsg) {
		t.Errorf("Expected error to contain %q, got %q", expectedMsg, err.Error())
	}
}

func TestLibdnsRecordToNjalla_ARecord(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  time.Hour,
		IP:   netip.MustParseAddr("192.0.2.1"),
		ProviderData: map[string]string{
			"id": "test-id",
		},
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got %s", result.ID)
	}

	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", result.Domain)
	}

	if result.Type != "A" {
		t.Errorf("Expected type 'A', got %s", result.Type)
	}

	if result.Name != "test" {
		t.Errorf("Expected name 'test', got %s", result.Name)
	}

	if result.Content != "192.0.2.1" {
		t.Errorf("Expected content '192.0.2.1', got %s", result.Content)
	}

	if result.TTL != 3600 {
		t.Errorf("Expected TTL 3600, got %d", result.TTL)
	}
}

func TestLibdnsRecordToNjalla_AAAARecord(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  time.Hour,
		IP:   netip.MustParseAddr("2001:db8::1"),
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "AAAA" {
		t.Errorf("Expected type 'AAAA', got %s", result.Type)
	}

	if result.Content != "2001:db8::1" {
		t.Errorf("Expected content '2001:db8::1', got %s", result.Content)
	}
}

func TestLibdnsRecordToNjalla_CNAMERecord(t *testing.T) {
	record := libdns.CNAME{
		Name:   "www",
		TTL:    30 * time.Minute,
		Target: "example.com",
		ProviderData: map[string]string{
			"id": "cname-id",
		},
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.ID != "cname-id" {
		t.Errorf("Expected ID 'cname-id', got %s", result.ID)
	}

	if result.Type != "CNAME" {
		t.Errorf("Expected type 'CNAME', got %s", result.Type)
	}

	if result.Name != "www" {
		t.Errorf("Expected name 'www', got %s", result.Name)
	}

	if result.Content != "example.com" {
		t.Errorf("Expected content 'example.com', got %s", result.Content)
	}

	if result.TTL != 1800 {
		t.Errorf("Expected TTL 1800, got %d", result.TTL)
	}
}

func TestLibdnsRecordToNjalla_TXTRecord(t *testing.T) {
	record := libdns.TXT{
		Name: "_dmarc",
		TTL:  2 * time.Hour,
		Text: "v=DMARC1; p=none",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "TXT" {
		t.Errorf("Expected type 'TXT', got %s", result.Type)
	}

	if result.Name != "_dmarc" {
		t.Errorf("Expected name '_dmarc', got %s", result.Name)
	}

	if result.Content != "v=DMARC1; p=none" {
		t.Errorf("Expected content 'v=DMARC1; p=none', got %s", result.Content)
	}

	if result.TTL != 7200 {
		t.Errorf("Expected TTL 7200, got %d", result.TTL)
	}
}

func TestLibdnsRecordToNjalla_MXRecord(t *testing.T) {
	record := libdns.MX{
		Name:       "@",
		TTL:        time.Hour,
		Preference: 10,
		Target:     "mail.example.com",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "MX" {
		t.Errorf("Expected type 'MX', got %s", result.Type)
	}

	if result.Name != "@" {
		t.Errorf("Expected name '@', got %s", result.Name)
	}

	if result.Content != "mail.example.com" {
		t.Errorf("Expected content 'mail.example.com', got %s", result.Content)
	}

	if result.Prio != 10 {
		t.Errorf("Expected prio 10, got %d", result.Prio)
	}
}

func TestLibdnsRecordToNjalla_SRVRecord(t *testing.T) {
	record := libdns.SRV{
		Name:     "_sip._tcp",
		TTL:      time.Hour,
		Priority: 10,
		Weight:   20,
		Port:     5060,
		Target:   "sip.example.com",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "SRV" {
		t.Errorf("Expected type 'SRV', got %s", result.Type)
	}

	if result.Name != "_sip._tcp" {
		t.Errorf("Expected name '_sip._tcp', got %s", result.Name)
	}

	if result.Content != "sip.example.com" {
		t.Errorf("Expected content 'sip.example.com', got %s", result.Content)
	}

	if result.Prio != 10 {
		t.Errorf("Expected prio 10, got %d", result.Prio)
	}

	if result.Weight != 20 {
		t.Errorf("Expected weight 20, got %d", result.Weight)
	}

	if result.Port != 5060 {
		t.Errorf("Expected port 5060, got %d", result.Port)
	}
}

func TestLibdnsRecordToNjalla_RRRecord(t *testing.T) {
	record := libdns.RR{
		Name: "@",
		TTL:  24 * time.Hour,
		Type: "NS",
		Data: "ns1.example.com",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "NS" {
		t.Errorf("Expected type 'NS', got %s", result.Type)
	}

	if result.Name != "@" {
		t.Errorf("Expected name '@', got %s", result.Name)
	}

	if result.Content != "ns1.example.com" {
		t.Errorf("Expected content 'ns1.example.com', got %s", result.Content)
	}

	if result.TTL != 86400 {
		t.Errorf("Expected TTL 86400, got %d", result.TTL)
	}
}

func TestLibdnsRecordToNjalla_RelativeName(t *testing.T) {
	tests := []struct {
		name     string
		record   libdns.Record
		zone     string
		expected string
	}{
		{
			name: "absolute name with zone",
			record: libdns.Address{
				Name: "test.example.com.",
				IP:   netip.MustParseAddr("192.0.2.1"),
			},
			zone:     "example.com",
			expected: "test",
		},
		{
			name: "relative name",
			record: libdns.Address{
				Name: "test",
				IP:   netip.MustParseAddr("192.0.2.1"),
			},
			zone:     "example.com",
			expected: "test",
		},
		{
			name: "root record",
			record: libdns.Address{
				Name: "@",
				IP:   netip.MustParseAddr("192.0.2.1"),
			},
			zone:     "example.com",
			expected: "@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := libdnsRecordToNjalla(tt.record, tt.zone)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Name != tt.expected {
				t.Errorf("Expected name %q, got %q", tt.expected, result.Name)
			}
		})
	}
}

// Create a custom record type that's not supported for testing
type unsupportedRecord struct {
	name string
	ttl  time.Duration
	typ  string
	data string
}

// Implement the libdns.Record interface
func (u unsupportedRecord) RR() libdns.RR {
	return libdns.RR{
		Name: u.name,
		TTL:  u.ttl,
		Type: u.typ,
		Data: u.data,
	}
}

func TestLibdnsRecordToNjalla_UnsupportedRecord(t *testing.T) {
	record := unsupportedRecord{
		name: "test",
		ttl:  time.Hour,
		typ:  "UNSUPPORTED",
		data: "test-data",
	}

	_, err := libdnsRecordToNjalla(record, "example.com")
	if err == nil {
		t.Fatal("Expected error for unsupported record type")
	}

	expectedMsg := "unsupported record type"
	if !containsString(err.Error(), expectedMsg) {
		t.Errorf("Expected error to contain %q, got %q", expectedMsg, err.Error())
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				func() bool {
					for i := 1; i < len(s)-len(substr)+1; i++ {
						if s[i:i+len(substr)] == substr {
							return true
						}
					}
					return false
				}())))
}

// Test table-driven approach for multiple record conversions
func TestRecordConversions_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		njallaRecord njallaRecord
		expectedType string
		shouldError  bool
	}{
		{
			name: "valid A record",
			njallaRecord: njallaRecord{
				ID: "1", Type: "A", Name: "test", Content: "192.0.2.1", TTL: 3600,
			},
			expectedType: "libdns.Address",
			shouldError:  false,
		},
		{
			name: "valid AAAA record",
			njallaRecord: njallaRecord{
				ID: "2", Type: "AAAA", Name: "test", Content: "2001:db8::1", TTL: 3600,
			},
			expectedType: "libdns.Address",
			shouldError:  false,
		},
		{
			name: "valid CNAME record",
			njallaRecord: njallaRecord{
				ID: "3", Type: "CNAME", Name: "www", Content: "example.com", TTL: 1800,
			},
			expectedType: "libdns.CNAME",
			shouldError:  false,
		},
		{
			name: "valid TXT record",
			njallaRecord: njallaRecord{
				ID: "4", Type: "TXT", Name: "_dmarc", Content: "v=DMARC1; p=none", TTL: 7200,
			},
			expectedType: "libdns.TXT",
			shouldError:  false,
		},
		{
			name: "valid MX record",
			njallaRecord: njallaRecord{
				ID: "5", Type: "MX", Name: "@", Content: "mail.example.com", TTL: 3600, Prio: 10,
			},
			expectedType: "libdns.MX",
			shouldError:  false,
		},
		{
			name: "valid SRV record",
			njallaRecord: njallaRecord{
				ID: "6", Type: "SRV", Name: "_sip._tcp", Content: "sip.example.com",
				TTL: 3600, Prio: 10, Weight: 20, Port: 5060,
			},
			expectedType: "libdns.SRV",
			shouldError:  false,
		},
		{
			name: "generic NS record",
			njallaRecord: njallaRecord{
				ID: "7", Type: "NS", Name: "@", Content: "ns1.example.com", TTL: 86400,
			},
			expectedType: "libdns.RR",
			shouldError:  false,
		},
		{
			name: "invalid A record",
			njallaRecord: njallaRecord{
				ID: "8", Type: "A", Name: "test", Content: "invalid-ip", TTL: 3600,
			},
			expectedType: "",
			shouldError:  true,
		},
		{
			name: "invalid AAAA record",
			njallaRecord: njallaRecord{
				ID: "9", Type: "AAAA", Name: "test", Content: "invalid-ipv6", TTL: 3600,
			},
			expectedType: "",
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := njallaRecordToLibdns(tt.njallaRecord)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check the type of the result
			var actualType string
			switch result.(type) {
			case libdns.Address:
				actualType = "libdns.Address"
			case libdns.CNAME:
				actualType = "libdns.CNAME"
			case libdns.TXT:
				actualType = "libdns.TXT"
			case libdns.MX:
				actualType = "libdns.MX"
			case libdns.SRV:
				actualType = "libdns.SRV"
			case libdns.RR:
				actualType = "libdns.RR"
			default:
				actualType = "unknown"
			}

			if actualType != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, actualType)
			}
		})
	}
}

func TestLibdnsRecordToNjalla_RecordWithoutProviderData(t *testing.T) {
	tests := []struct {
		name   string
		record libdns.Record
	}{
		{
			name: "Address without ProviderData",
			record: libdns.Address{
				Name: "test",
				TTL:  time.Hour,
				IP:   netip.MustParseAddr("192.0.2.1"),
				// No ProviderData
			},
		},
		{
			name: "CNAME without ProviderData",
			record: libdns.CNAME{
				Name:   "www",
				TTL:    30 * time.Minute,
				Target: "example.com",
				// No ProviderData
			},
		},
		{
			name: "TXT without ProviderData",
			record: libdns.TXT{
				Name: "_dmarc",
				TTL:  2 * time.Hour,
				Text: "v=DMARC1; p=none",
				// No ProviderData
			},
		},
		{
			name: "MX without ProviderData",
			record: libdns.MX{
				Name:       "@",
				TTL:        time.Hour,
				Preference: 10,
				Target:     "mail.example.com",
				// No ProviderData
			},
		},
		{
			name: "SRV without ProviderData",
			record: libdns.SRV{
				Name:     "_sip._tcp",
				TTL:      time.Hour,
				Priority: 10,
				Weight:   20,
				Port:     5060,
				Target:   "sip.example.com",
				// No ProviderData
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := libdnsRecordToNjalla(tt.record, "example.com")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// ID should be empty when no ProviderData
			if result.ID != "" {
				t.Errorf("Expected empty ID, got %s", result.ID)
			}

			// Other fields should be set correctly
			if result.Domain != "example.com" {
				t.Errorf("Expected domain 'example.com', got %s", result.Domain)
			}
		})
	}
}

func TestLibdnsRecordToNjalla_InvalidProviderData(t *testing.T) {
	tests := []struct {
		name         string
		record       libdns.Record
		expectedType string
	}{
		{
			name: "Address with invalid ProviderData type",
			record: libdns.Address{
				Name:         "test",
				TTL:          time.Hour,
				IP:           netip.MustParseAddr("192.0.2.1"),
				ProviderData: "invalid-string", // Should be map[string]string
			},
			expectedType: "A",
		},
		{
			name: "CNAME with invalid ProviderData type",
			record: libdns.CNAME{
				Name:         "www",
				TTL:          30 * time.Minute,
				Target:       "example.com",
				ProviderData: 123, // Should be map[string]string
			},
			expectedType: "CNAME",
		},
		{
			name: "TXT with invalid ProviderData type",
			record: libdns.TXT{
				Name:         "_dmarc",
				TTL:          2 * time.Hour,
				Text:         "v=DMARC1; p=none",
				ProviderData: []string{"invalid", "slice"}, // Should be map[string]string
			},
			expectedType: "TXT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := libdnsRecordToNjalla(tt.record, "example.com")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Should handle invalid ProviderData gracefully
			if result.ID != "" {
				t.Errorf("Expected empty ID with invalid ProviderData, got %s", result.ID)
			}

			if result.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, result.Type)
			}
		})
	}
}

func TestLibdnsRecordToNjalla_ProviderDataWithoutID(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  time.Hour,
		IP:   netip.MustParseAddr("192.0.2.1"),
		ProviderData: map[string]string{
			"other_field": "value",
			// No "id" key
		},
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// ID should be empty when not present in ProviderData
	if result.ID != "" {
		t.Errorf("Expected empty ID, got %s", result.ID)
	}
}

func TestLibdnsRecordToNjalla_EmptyProviderDataMap(t *testing.T) {
	record := libdns.Address{
		Name:         "test",
		TTL:          time.Hour,
		IP:           netip.MustParseAddr("192.0.2.1"),
		ProviderData: map[string]string{}, // Empty map
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// ID should be empty with empty map
	if result.ID != "" {
		t.Errorf("Expected empty ID, got %s", result.ID)
	}
}

func TestLibdnsRecordToNjalla_RRRecordLimitation(t *testing.T) {
	// Test the limitation that RR records don't support ProviderData
	record := libdns.RR{
		Name: "@",
		TTL:  24 * time.Hour,
		Type: "NS",
		Data: "ns1.example.com",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// RR records can't have IDs due to libdns limitation
	if result.ID != "" {
		t.Errorf("Expected empty ID for RR record, got %s", result.ID)
	}

	if result.Type != "NS" {
		t.Errorf("Expected type 'NS', got %s", result.Type)
	}

	if result.Content != "ns1.example.com" {
		t.Errorf("Expected content 'ns1.example.com', got %s", result.Content)
	}
}

func TestLibdnsRecordToNjalla_ZeroTTL(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  0, // Zero TTL
		IP:   netip.MustParseAddr("192.0.2.1"),
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.TTL != 0 {
		t.Errorf("Expected TTL 0, got %d", result.TTL)
	}
}

func TestLibdnsRecordToNjalla_LargeTTL(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  24 * 365 * time.Hour, // 1 year
		IP:   netip.MustParseAddr("192.0.2.1"),
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedTTL := int((24 * 365 * time.Hour).Seconds())
	if result.TTL != expectedTTL {
		t.Errorf("Expected TTL %d, got %d", expectedTTL, result.TTL)
	}
}

func TestLibdnsRecordToNjalla_IPv6Address(t *testing.T) {
	record := libdns.Address{
		Name: "test",
		TTL:  time.Hour,
		IP:   netip.MustParseAddr("2001:db8::1"),
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Type != "AAAA" {
		t.Errorf("Expected type 'AAAA', got %s", result.Type)
	}

	if result.Content != "2001:db8::1" {
		t.Errorf("Expected content '2001:db8::1', got %s", result.Content)
	}
}

func TestLibdnsRecordToNjalla_IPv4MappedIPv6(t *testing.T) {
	// Test IPv4-mapped IPv6 address
	record := libdns.Address{
		Name: "test",
		TTL:  time.Hour,
		IP:   netip.MustParseAddr("::ffff:192.0.2.1"),
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should be treated as AAAA since it's an IPv6 address
	if result.Type != "AAAA" {
		t.Errorf("Expected type 'AAAA', got %s", result.Type)
	}

	if result.Content != "::ffff:192.0.2.1" {
		t.Errorf("Expected content '::ffff:192.0.2.1', got %s", result.Content)
	}
}

func TestLibdnsRecordToNjalla_SRVRecordWithZeroValues(t *testing.T) {
	record := libdns.SRV{
		Name:     "_sip._tcp",
		TTL:      time.Hour,
		Priority: 0,
		Weight:   0,
		Port:     0,
		Target:   ".",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Prio != 0 {
		t.Errorf("Expected prio 0, got %d", result.Prio)
	}

	if result.Weight != 0 {
		t.Errorf("Expected weight 0, got %d", result.Weight)
	}

	if result.Port != 0 {
		t.Errorf("Expected port 0, got %d", result.Port)
	}

	if result.Content != "." {
		t.Errorf("Expected target '.', got %s", result.Content)
	}
}

func TestLibdnsRecordToNjalla_MXRecordWithHighPreference(t *testing.T) {
	record := libdns.MX{
		Name:       "@",
		TTL:        time.Hour,
		Preference: 65535, // Max uint16 value
		Target:     "mail.example.com",
	}

	result, err := libdnsRecordToNjalla(record, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Prio != 65535 {
		t.Errorf("Expected prio 65535, got %d", result.Prio)
	}
}

// Test complex name scenarios
func TestLibdnsRecordToNjalla_ComplexNames(t *testing.T) {
	tests := []struct {
		name         string
		recordName   string
		zone         string
		expectedName string
	}{
		{
			name:         "simple subdomain",
			recordName:   "test",
			zone:         "example.com",
			expectedName: "test",
		},
		{
			name:         "multiple subdomains",
			recordName:   "a.b.c",
			zone:         "example.com",
			expectedName: "a.b.c",
		},
		{
			name:         "root record with @",
			recordName:   "@",
			zone:         "example.com",
			expectedName: "@",
		},
		{
			name:         "empty name",
			recordName:   "",
			zone:         "example.com",
			expectedName: "",
		},
		{
			name:         "wildcard record",
			recordName:   "*",
			zone:         "example.com",
			expectedName: "*",
		},
		{
			name:         "wildcard subdomain",
			recordName:   "*.sub",
			zone:         "example.com",
			expectedName: "*.sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := libdns.Address{
				Name: tt.recordName,
				TTL:  time.Hour,
				IP:   netip.MustParseAddr("192.0.2.1"),
			}

			result, err := libdnsRecordToNjalla(record, tt.zone)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Name != tt.expectedName {
				t.Errorf("Expected name %q, got %q", tt.expectedName, result.Name)
			}
		})
	}
}
