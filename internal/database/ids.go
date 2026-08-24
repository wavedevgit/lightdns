package database

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func newPublicID(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate public ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(random), nil
}
