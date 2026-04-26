package common

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestStringToHashBase64(t *testing.T) {
	for _, tt := range [...]struct {
		Name   string
		Input  string
		Expect string
	}{
		{
			Name:  "known value for hello",
			Input: "hello",
			Expect: base64.StdEncoding.EncodeToString(func() []byte {
				h := sha256.Sum256([]byte("hello"))
				return h[:]
			}()),
		},
		{
			Name:  "empty string produces non-empty hash",
			Input: "",
			Expect: base64.StdEncoding.EncodeToString(func() []byte {
				h := sha256.Sum256([]byte(""))
				return h[:]
			}()),
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			got := StringToHashBase64(tt.Input)
			if got != tt.Expect {
				t.Errorf("StringToHashBase64(%q) = %q, want %q", tt.Input, got, tt.Expect)
			}
		})
	}
}

func TestStringToHashBase64_Deterministic(t *testing.T) {
	a := StringToHashBase64("test-token-123")
	b := StringToHashBase64("test-token-123")
	if a != b {
		t.Errorf("same input produced different hashes: %q vs %q", a, b)
	}
}

func TestStringToHashBase64_DifferentInputs(t *testing.T) {
	a := StringToHashBase64("input-a")
	b := StringToHashBase64("input-b")
	if a == b {
		t.Errorf("different inputs produced same hash: %q", a)
	}
}

func TestStringArrayOpt(t *testing.T) {
	sa := []string{" a ", " b ", " c "}
	StringArrayOpt(sa, func(s string) string {
		return s[1 : len(s)-1]
	})
	for i, want := range []string{"a", "b", "c"} {
		if sa[i] != want {
			t.Errorf("sa[%d] = %q, want %q", i, sa[i], want)
		}
	}
}
