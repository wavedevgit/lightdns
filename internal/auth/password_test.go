package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") || strings.Contains(encoded, "correct horse") {
		t.Fatalf("unexpected password hash %q", encoded)
	}
	matched, err := VerifyPassword(encoded, "correct horse battery staple")
	if err != nil || !matched {
		t.Fatalf("correct password matched = %v, err = %v", matched, err)
	}
	matched, err = VerifyPassword(encoded, "wrong password")
	if err != nil || matched {
		t.Fatalf("wrong password matched = %v, err = %v", matched, err)
	}
}

func TestHashPasswordValidatesLength(t *testing.T) {
	if _, err := HashPassword("too short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password error = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", maximumPasswordBytes+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("long password error = %v", err)
	}
}

func TestVerifyPasswordRejectsUnsafeHashParameters(t *testing.T) {
	tests := []string{
		"plaintext",
		"$argon2id$v=18$m=65536,t=3,p=2$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=999999,t=3,p=2$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=0,p=2$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$not-base64!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		strings.Repeat("x", 513),
	}
	for _, encoded := range tests {
		if _, err := VerifyPassword(encoded, "irrelevant password"); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("VerifyPassword(%q) error = %v", encoded, err)
		}
	}
}

func TestVerifyPasswordRejectsInvalidInputAfterHashWork(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{strings.Repeat("x", maximumPasswordBytes+1), string([]byte{0xff, 0xfe})} {
		matched, err := VerifyPassword(encoded, password)
		if err != nil || matched {
			t.Errorf("invalid password matched = %v, err = %v", matched, err)
		}
	}
}
