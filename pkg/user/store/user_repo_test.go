package store

import "testing"

func TestInferIdentifierColumn(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"alice", "username"},
		{"bob_smith", "username"},
		{"alice@example.com", "email"},
		{"user@company.org", "email"},
		{"+8613800138000", "phone"},
		{"+1234567890", "phone"},
		{"13800138000", "phone"},
		{"0123456789", "phone"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := inferIdentifierColumn(tt.input)
			if got != tt.want {
				t.Errorf("inferIdentifierColumn(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsAllDigits(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123456", true},
		{"0", true},
		{"", false},
		{"12a34", false},
		{"+123", false},
		{"12.34", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isAllDigits(tt.input)
			if got != tt.want {
				t.Errorf("isAllDigits(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
