package parser

import (
	"fmt"
	"reflect"
	"testing"
)

func TestContextualizer_IgnoreLogic(t *testing.T) {
	c := NewContextualizer(true, []string{"nullferatu.com", "google.com"}, []string{"admin@test.com"})

	tests := []struct {
		name     string
		input    string
		kind     string
		expected []Match
	}{
		{
			name:     "Ignore base domain",
			input:    "Visit nullferatu.com",
			kind:     "domain",
			expected: nil,
		},
		{
			name:     "Ignore subdomain",
			input:    "Visit fair.nullferatu.com",
			kind:     "domain",
			expected: nil,
		},
		{
			name:     "Ignore email via domain",
			input:    "Contact support@nullferatu.com",
			kind:     "email",
			expected: nil,
		},
		{
			name:     "Ignore URL via domain",
			input:    "Link: https://fair.nullferatu.com/path",
			kind:     "url",
			expected: nil,
		},
		{
			name:     "Allow non-ignored domain",
			input:    "Visit example.com",
			kind:     "domain",
			expected: []Match{{Value: "example.com", Type: "domain"}},
		},
		{
			name:     "Ignore private IP",
			input:    "IP is 192.168.1.1",
			kind:     "ipv4",
			expected: nil,
		},
		{
			name:     "Allow public IP",
			input:    "IP is 8.8.8.8",
			kind:     "ipv4",
			expected: []Match{{Value: "8.8.8.8", Type: "ipv4"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.GetMatches(tt.input, tt.kind, c.Expressions[tt.kind])
			fmt.Println("Got matches:", got, "Expected matches:", tt.expected)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("GetMatches() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestContextualizer_ExtractAll(t *testing.T) {
	c := NewContextualizer(false, []string{"ignored.com"}, nil)
	text := "Check out http://example.com/page, contact dev@example.com or visit sub.test.org"

	results := c.ExtractAll(text)

	if len(results["url"]) != 1 || results["url"][0].Value != "http://example.com/page" {
		t.Errorf("URL extraction failed: %v", results["url"])
	}

	// Ensure base_domain is extracted for the domain match
	foundBase := false
	for _, m := range results["base_domain"] {
		if m.Value == "test.org" {
			foundBase = true
		}
	}
	if !foundBase {
		t.Errorf("Base domain 'test.org' not extracted from 'sub.test.org'")
	}
}
