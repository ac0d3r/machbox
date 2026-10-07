package ioc

import (
	"reflect"
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
			input:    "PropertyList-1.0.dtd config.plist lib.rs main.pl run.sh README.md script.fm file.st Makefile.am Foo.app archive.zip",
			expected: nil,
		},
		{
			name:     "rs tld in url is still kept",
			input:    "https://example.rs/path",
			expected: []string{"https://example.rs/path"},
		},
		{
			name:     "url trailing punctuation is stripped",
			input:    "see https://evil.com/path).",
			expected: []string{"evil.com", "https://evil.com/path"},
		},
		{
			name:     "fake email with file extension rejected",
			input:    "admin@foo.dtd",
			expected: nil,
		},
		{
			name:     "email local part is not a domain",
			input:    "user.name+tag@sub.domain.io",
			expected: []string{"sub.domain.io", "user.name+tag@sub.domain.io"},
		},
		{
			name:     "bundle ids are not domains",
			input:    "CFBundle.com.apple.ls com.apple.Safari",
			expected: nil,
		},
		{
			name:     "edu and gov domains are extracted",
			input:    "goto university.edu and host.gov.uk",
			expected: []string{"host.gov.uk", "university.edu"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &IOCExtractor{}
			e.Extract(tc.input)
			got := e.Export()
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
