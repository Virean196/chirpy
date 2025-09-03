package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test password hashing and checking
func TestHashPasswordAndCheck(t *testing.T) {
	password := "superSecret123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("expected no error hashing password, got %v", err)
	}
	if hash == password {
		t.Fatalf("hash should not match raw password")
	}

	// Check correct password
	if err := CheckPasswordHash(hash, password); err != nil {
		t.Fatalf("expected password to match hash, got %v", err)
	}

	// Check incorrect password
	if err := CheckPasswordHash(hash, "wrongPass"); err == nil {
		t.Fatalf("expected error for wrong password, got none")
	}
}

// Test MakeJWT and ValidateJWT
func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testSecret"
	expiration := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiration)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if parsedID != userID {
		t.Fatalf("expected userID %v, got %v", userID, parsedID)
	}
}

// Test expired token validation
func TestExpiredJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testSecret"
	expiration := -time.Minute // already expired

	token, err := MakeJWT(userID, secret, expiration)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error for expired token, got none")
	}

	// Check that the error message contains "expired"
	if !containsIgnoreCase(err.Error(), "expired") {
		t.Fatalf("expected error to mention 'expired', got: %v", err)
	}
}

// Helper to make case-insensitive substring checks
func containsIgnoreCase(str, substr string) bool {
	return len(str) >= len(substr) &&
		(strings.Contains(strings.ToLower(str), strings.ToLower(substr)))
}

// Test invalid signature
func TestInvalidSignatureJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testSecret"
	wrongSecret := "wrongSecret"
	expiration := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiration)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatalf("expected error for invalid signature, got none")
	}
}

// Test tampered token
func TestTamperedJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testSecret"
	expiration := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiration)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Tamper token by changing a character
	tamperedToken := token[:len(token)-1] + "x"

	_, err = ValidateJWT(tamperedToken, secret)
	if err == nil {
		t.Fatalf("expected error for tampered token, got none")
	}
}
