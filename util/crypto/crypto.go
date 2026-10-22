// Package crypto provides cryptographic utilities for password hashing and verification.
package crypto

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	CredentialBcrypt      = "bcrypt"
	CredentialSHA384      = "sha384"
	prehashedBcryptPrefix = "$xui$bcrypt-sha384$"
)

// HashPasswordAsBcrypt generates a bcrypt hash of the given password.
func HashPasswordAsBcrypt(password string) (string, error) {
	input := []byte(password)
	prefix := ""
	// A legacy SHA-384 account can have a password longer than bcrypt's limit.
	// Tag the encoding so verification never silently truncates the password.
	if len(input) > 72 {
		digest := sha512.Sum384(input)
		input = digest[:]
		prefix = prehashedBcryptPrefix
	}
	hash, err := bcrypt.GenerateFromPassword(input, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return prefix + string(hash), nil
}

// CheckPasswordHash verifies if the given password matches the bcrypt hash.
func CheckPasswordHash(hash, password string) bool {
	input := []byte(password)
	if strings.HasPrefix(hash, prehashedBcryptPrefix) {
		hash = strings.TrimPrefix(hash, prehashedBcryptPrefix)
		digest := sha512.Sum384(input)
		input = digest[:]
	} else if len(input) > 72 {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), input)
	return err == nil
}

func IsBcryptHash(hash string) bool {
	hash = strings.TrimPrefix(hash, prehashedBcryptPrefix)
	_, err := bcrypt.Cost([]byte(hash))
	return len(hash) == 60 && err == nil
}

func SHA384Hash(value string) string {
	digest := sha512.Sum384([]byte(value))
	return hex.EncodeToString(digest[:])
}

func IsSHA384Hash(value string) bool {
	if len(value) != sha512.Size384*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func CheckSHA384Hash(hash, value string) bool {
	stored, err := hex.DecodeString(hash)
	if err != nil || len(stored) != sha512.Size384 {
		return false
	}
	digest := sha512.Sum384([]byte(value))
	return subtle.ConstantTimeCompare(stored, digest[:]) == 1
}
