package auth

import (
	"testing"
)

func TestCheckPasswordPolicy(t *testing.T) {
	tests := []struct {
		password string
		wantErr  error
	}{
		{"short", ErrPasswordTooShort},
		{"valid password", nil},
	}

	for _, tt := range tests {
		err := CheckPasswordPolicy(tt.password)
		if err != tt.wantErr {
			t.Errorf("CheckPasswordPolicy(%q) = %v; want %v", tt.password, err, tt.wantErr)
		}
	}
}

func TestValidatePasswordChange(t *testing.T) {
	currentPassword := "current password"
	currentHash, err := GeneratePasswordHash(currentPassword)
	if err != nil {
		t.Fatalf("failed to generate password hash: %v", err)
	}

	tests := []struct {
		newPassword     string
		confirmPassword string
		wantErr         error
	}{
		{"valid password", "invalid", ErrPasswordMismatch},
		{currentPassword, currentPassword, ErrReusedPassword},
		{"newStrongPass1!", "newStrongPass1!", nil}, // Assuming this is valid and different
	}

	for _, tt := range tests {
		_, err := ValidatePasswordChange(currentHash, tt.newPassword, tt.confirmPassword)
		if err != tt.wantErr {
			t.Errorf("ValidatePasswordChange(%q, %q) = %v; want %v", tt.newPassword, tt.confirmPassword, err, tt.wantErr)
		}
	}
}
