package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinimumPasswordLength = 12
	maximumPasswordBytes  = 1024
	argonMemory           = 64 * 1024
	argonIterations       = 3
	argonParallelism      = 2
	argonSaltLength       = 16
	argonKeyLength        = 32
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must contain at least %d characters", MinimumPasswordLength)
	ErrPasswordTooLong  = errors.New("password is too long")
	ErrInvalidPassword  = errors.New("password must be valid UTF-8")
	ErrInvalidHash      = errors.New("password hash is invalid")
)

type argonParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) (bool, error) {
	parameters, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	validPassword := len(password) <= maximumPasswordBytes && utf8.ValidString(password)
	if !validPassword {
		password = "invalid password input"
	}
	key := argon2.IDKey([]byte(password), parameters.salt, parameters.iterations, parameters.memory, parameters.parallelism, uint32(len(parameters.key)))
	return validPassword && subtle.ConstantTimeCompare(key, parameters.key) == 1, nil
}

func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrInvalidPassword
	}
	if len(password) > maximumPasswordBytes {
		return ErrPasswordTooLong
	}
	if utf8.RuneCountInString(password) < MinimumPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

func parseHash(encoded string) (argonParameters, error) {
	if len(encoded) < 20 || len(encoded) > 512 {
		return argonParameters{}, ErrInvalidHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return argonParameters{}, ErrInvalidHash
	}
	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return argonParameters{}, ErrInvalidHash
	}
	memory, err := parseParameter(parameterParts[0], "m=")
	if err != nil || memory < 8*1024 || memory > argonMemory {
		return argonParameters{}, ErrInvalidHash
	}
	iterations, err := parseParameter(parameterParts[1], "t=")
	if err != nil || iterations < 1 || iterations > argonIterations {
		return argonParameters{}, ErrInvalidHash
	}
	parallelism, err := parseParameter(parameterParts[2], "p=")
	if err != nil || parallelism < 1 || parallelism > argonParallelism {
		return argonParameters{}, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return argonParameters{}, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) != argonKeyLength {
		return argonParameters{}, ErrInvalidHash
	}
	return argonParameters{
		memory: uint32(memory), iterations: uint32(iterations), parallelism: uint8(parallelism), salt: salt, key: key,
	}, nil
}

func parseParameter(value, prefix string) (uint64, error) {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return 0, ErrInvalidHash
	}
	parsed, err := strconv.ParseUint(value[len(prefix):], 10, 32)
	if err != nil {
		return 0, ErrInvalidHash
	}
	return parsed, nil
}
