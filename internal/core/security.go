package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const rounds = 210000

var ErrPasswordLength = errors.New("password must be 8-256 bytes")

func RandomToken(n int) (string, error) {
	if n < 16 || n > 256 {
		return "", errors.New("invalid random length")
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	var result []byte
	for block := 1; len(result) < keyLen; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}
func HashPassword(p string) (string, error) {
	if len(p) < 8 || len(p) > 256 {
		return "", ErrPasswordLength
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", rounds, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(pbkdf2([]byte(p), salt, rounds, 32))), nil
}
func VerifyPassword(encoded, p string) bool {
	if len(p) > 256 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	n, e := strconv.Atoi(parts[1])
	if e != nil || n < 1 || n > 1_000_000 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[2])
	if e != nil || len(salt) != 16 {
		return false
	}
	expected, e := base64.RawStdEncoding.DecodeString(parts[3])
	if e != nil || len(expected) != 32 {
		return false
	}
	got := pbkdf2([]byte(p), salt, n, 32)
	return subtle.ConstantTimeCompare(got, expected) == 1
}
