package core

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	h, e := HashPassword("correct horse battery staple")
	if e != nil {
		t.Fatal(e)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("failed correct password")
	}
	if VerifyPassword(h, "wrong") {
		t.Fatal("accepted incorrect password")
	}
	if _, e = HashPassword("short"); e == nil {
		t.Fatal("accepted short password")
	}
}

func TestPBKDF2SHA256KnownVectors(t *testing.T) {
	for _, tt := range []struct {
		rounds   int
		expected string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	} {
		got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), tt.rounds, 32))
		if got != tt.expected {
			t.Fatalf("PBKDF2 rounds %d: got %s", tt.rounds, got)
		}
	}
}

func TestVerifyPasswordRejectsMalformedOrOversizedInput(t *testing.T) {
	for _, encoded := range []string{"", "sha256$1$x$y", "pbkdf2-sha256$0$x$y", "pbkdf2-sha256$1000001$x$y", "pbkdf2-sha256$1$broken$broken"} {
		if VerifyPassword(encoded, "password") {
			t.Fatalf("accepted malformed hash %q", encoded)
		}
	}
	// Oversized passwords are rejected even if a legacy/custom hash encodes
	// the same value, avoiding repeated hashing of a large HMAC key.
	password := strings.Repeat("x", 257)
	salt := make([]byte, 16)
	encoded := "pbkdf2-sha256$1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(pbkdf2([]byte(password), salt, 1, 32))
	if VerifyPassword(encoded, password) {
		t.Fatal("accepted oversized password")
	}
}
