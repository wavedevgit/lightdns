package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	passwordauth "lightdns/internal/auth"
)

func TestCreateAndAuthenticateUser(t *testing.T) {
	store := openTestStore(t)
	admin, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "Primary.Admin", Password: "correct horse battery staple", Role: RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if admin.PublicID == "" || admin.ID == 0 || !admin.Enabled || admin.Role != RoleAdmin {
		t.Fatalf("created admin = %+v", admin)
	}
	if admin.PasswordHash != "" {
		t.Fatal("created user exposed a password hash")
	}
	var storedHash string
	if err := store.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", admin.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedHash, "correct horse") || !strings.HasPrefix(storedHash, "$argon2id$") {
		t.Fatalf("stored password hash = %q", storedHash)
	}

	login, err := store.CreateAuthenticatedSession(t.Context(), "primary.admin", "correct horse battery staple", 12*time.Hour)
	if err != nil || login.User.ID != admin.ID {
		t.Fatalf("authenticated user = %+v, err = %v", login.User, err)
	}
	if _, err := store.CreateAuthenticatedSession(t.Context(), "primary.admin", "incorrect password", time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := store.CreateAuthenticatedSession(t.Context(), "missing-user", "incorrect password", time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("missing user error = %v", err)
	}

	if _, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "PRIMARY.ADMIN", Password: "another secure password", Role: RoleUser,
	}); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate username error = %v", err)
	}
	if _, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "invalid space", Password: "another secure password", Role: RoleUser,
	}); err == nil {
		t.Fatal("invalid username was accepted")
	}
	if _, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "valid-user", Password: "short", Role: RoleUser,
	}); !errors.Is(err, passwordauth.ErrPasswordTooShort) {
		t.Fatalf("short password error = %v", err)
	}
}

func TestUserSecurityUpdatesAndListing(t *testing.T) {
	store := openTestStore(t)
	first, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "z-admin", Password: "first secure password", Role: RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateUser(t.Context(), CreateUserParams{
		Username: "a-admin", Password: "second secure password", Role: RoleAdmin, MustChangePassword: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := store.ListUsers(t.Context())
	if err != nil || len(users) != 2 || users[0].ID != second.ID || users[1].ID != first.ID {
		t.Fatalf("users = %+v, err = %v", users, err)
	}

	first, err = store.SetUserRole(t.Context(), first.PublicID, RoleUser)
	if err != nil || first.Role != RoleUser {
		t.Fatalf("demoted user = %+v, err = %v", first, err)
	}
	if _, err := store.SetUserEnabled(t.Context(), second.PublicID, false); err == nil {
		t.Fatal("last enabled admin was disabled")
	}
	if _, err := store.SetUserEnabled(t.Context(), "missing", false); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user update error = %v", err)
	}

	second, err = store.ResetPassword(t.Context(), second.PublicID, "temporary secure password", true)
	if err != nil || !second.MustChangePassword {
		t.Fatalf("reset user = %+v, err = %v", second, err)
	}
	if _, err := store.CreateAuthenticatedSession(t.Context(), second.Username, "second secure password", time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password error = %v", err)
	}
	second, err = store.ChangePassword(t.Context(), second.PublicID, "temporary secure password", "replacement secure password")
	if err != nil || second.MustChangePassword {
		t.Fatalf("changed user = %+v, err = %v", second, err)
	}
	if _, err := store.CreateAuthenticatedSession(t.Context(), second.Username, "replacement secure password", time.Hour); err != nil {
		t.Fatalf("authenticate replacement password: %v", err)
	}
	if _, err := store.ChangePassword(t.Context(), second.PublicID, "wrong current password", "unused secure password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password error = %v", err)
	}
}
