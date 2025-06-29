package njalla

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
)

// API request and response types

type listRecordsRequest struct {
	Domain string `json:"domain"`
}

type listRecordsResponse struct {
	Records []njallaRecord `json:"records"`
}

type addRecordRequest struct {
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Prio    int    `json:"prio,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Port    int    `json:"port,omitempty"`
	Target  string `json:"target,omitempty"`
}

type addRecordResponse struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Prio    int    `json:"prio,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Port    int    `json:"port,omitempty"`
	Target  string `json:"target,omitempty"`
}

type editRecordRequest struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Prio    int    `json:"prio,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Port    int    `json:"port,omitempty"`
	Target  string `json:"target,omitempty"`
}

type removeRecordRequest struct {
	Domain string `json:"domain"`
	ID     string `json:"id"`
}

// Njalla record structure
type njallaRecord struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Prio    int    `json:"prio,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Port    int    `json:"port,omitempty"`
	Target  string `json:"target,omitempty"`
}

// njallaRecordToLibdns converts a Njalla record to a libdns Record
func njallaRecordToLibdns(record njallaRecord) (libdns.Record, error) {
	// Set common fields
	recordTTL := time.Duration(record.TTL) * time.Second

	switch record.Type {
	case "A":
		ip, err := netip.ParseAddr(record.Content)
		if err != nil {
			return nil, fmt.Errorf("invalid A record IP address %q: %w", record.Content, err)
		}
		return libdns.Address{
			Name: record.Name,
			TTL:  recordTTL,
			IP:   ip,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	case "AAAA":
		ip, err := netip.ParseAddr(record.Content)
		if err != nil {
			return nil, fmt.Errorf("invalid AAAA record IP address %q: %w", record.Content, err)
		}
		return libdns.Address{
			Name: record.Name,
			TTL:  recordTTL,
			IP:   ip,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	case "CNAME":
		return libdns.CNAME{
			Name:   record.Name,
			TTL:    recordTTL,
			Target: record.Content,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	case "TXT":
		return libdns.TXT{
			Name: record.Name,
			TTL:  recordTTL,
			Text: record.Content,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	case "MX":
		return libdns.MX{
			Name:       record.Name,
			TTL:        recordTTL,
			Preference: uint16(record.Prio),
			Target:     record.Content,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	case "SRV":
		return libdns.SRV{
			Name:     record.Name,
			TTL:      recordTTL,
			Priority: uint16(record.Prio),
			Weight:   uint16(record.Weight),
			Port:     uint16(record.Port),
			Target:   record.Content,
			ProviderData: map[string]string{
				"id": record.ID,
			},
		}, nil

	default:
		// For other record types, use a generic RR
		return libdns.RR{
			Name: record.Name,
			TTL:  recordTTL,
			Type: record.Type,
			Data: record.Content,
		}, nil
	}
}

// libdnsRecordToNjalla converts a libdns.Record to a Njalla record
func libdnsRecordToNjalla(record libdns.Record, zone string) (njallaRecord, error) {
	// Start with default values
	rr := record.RR()
	result := njallaRecord{
		Domain: zone,
		Name:   libdns.RelativeName(rr.Name, zone+"."),
		TTL:    int(rr.TTL.Seconds()),
	}

	// Extract ID from ProviderData if available
	var id string
	
	// Handle each record type to extract the ID and other data
	switch r := record.(type) {
	case libdns.Address:
		result.Type = r.RR().Type
		result.Content = r.IP.String()
		if pd, ok := r.ProviderData.(map[string]string); ok {
			id = pd["id"]
		}

	case libdns.CNAME:
		result.Type = "CNAME"
		result.Content = r.Target
		if pd, ok := r.ProviderData.(map[string]string); ok {
			id = pd["id"]
		}

	case libdns.TXT:
		result.Type = "TXT"
		result.Content = r.Text
		if pd, ok := r.ProviderData.(map[string]string); ok {
			id = pd["id"]
		}

	case libdns.MX:
		result.Type = "MX"
		result.Content = r.Target
		result.Prio = int(r.Preference)
		if pd, ok := r.ProviderData.(map[string]string); ok {
			id = pd["id"]
		}

	case libdns.SRV:
		result.Type = "SRV"
		result.Content = r.Target
		result.Prio = int(r.Priority)
		result.Weight = int(r.Weight)
		result.Port = int(r.Port)
		if pd, ok := r.ProviderData.(map[string]string); ok {
			id = pd["id"]
		}

	case libdns.RR:
		result.Type = r.Type
		result.Content = r.Data
		// RR types don't have ProviderData, but we can store ID in a standardized way
		// This is a limitation - libdns.RR doesn't support ProviderData
		
	default:
		return result, fmt.Errorf("unsupported record type: %T", record)
	}

	// Set the ID if we found one
	if id != "" {
		result.ID = id
	}

	return result, nil
}

