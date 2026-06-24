package ioc

import (
	"sort"
	"testing"
)

func TestIOCExtractor(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "rust filenames are not iocs",
			input:    "settings.rs map.rs fmt.rs socket.rs",
			expected: nil,
		},
		{
			name:     "real domains are extracted",
			input:    "contact example.com or sub.example.co.uk for help",
			expected: []string{"example.com", "sub.example.co.uk"},
		},
		{
			name:     "ips emails and urls are extracted",
			input:    "visit https://example.com/path and email admin@example.com or 192.168.1.1",
			expected: []string{"192.168.1.1", "admin@example.com", "example.com", "https://example.com/path"},
		},
		{
			name:     "file extensions are not domains",
			input:    "PropertyList-1.0.dtd config.plist lib.rs main.pl run.sh README.md script.fm file.st Makefile.am",
			expected: nil,
		},
		{
			name:     "rs tld in url is still kept",
			input:    "https://example.rs/path",
			expected: []string{"https://example.rs/path"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &IOCExtractor{}
			e.Extract(tc.input)
			got := e.Export()
			sort.Strings(got)
			sort.Strings(tc.expected)

			if len(got) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected %v, got %v", tc.expected, got)
				}
			}
		})
	}
}
