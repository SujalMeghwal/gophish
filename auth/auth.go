package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 8
	APIKeyLength      = 32
)

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrPasswordMismatch  = errors.New("passwords do not match")
	ErrReusedPassword    = errors.New("cannot reuse existing password")
	ErrEmptyPassword     = errors.New("no password provided")
	ErrPasswordTooShort  = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordWeak      = errors.New("password must include uppercase, lowercase, digit, and special character")
)

func GenerateSecureKey(n int) (string, error) {
	k := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k), nil
}

func GeneratePasswordHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func PasswordNeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost < bcrypt.DefaultCost
}

func CheckPasswordPolicy(password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}

	var (
		hasUpper = false
		hasLower = false
		hasDigit = false
		hasSpec  = false
	)

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpec = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpec {
		return ErrPasswordWeak
	}

	return nil
}

func ValidatePassword(password string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func ValidatePasswordChange(currentHash, newPassword, confirmPassword string) (string, error) {
	if err := CheckPasswordPolicy(newPassword); err != nil {
		return "", err
	}

	if newPassword != confirmPassword {
		return "", ErrPasswordMismatch
	}

	if err := ValidatePassword(newPassword, currentHash); err == nil {
		return "", ErrReusedPassword
	}

	return GeneratePasswordHash(newPassword)
}
