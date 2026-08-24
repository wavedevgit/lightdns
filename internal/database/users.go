package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	passwordauth "lightdns/internal/auth"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUsernameTaken      = errors.New("username is already in use")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserChanged        = errors.New("user changed during the operation")
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type CreateUserParams struct {
	Username           string
	Password           string
	Role               UserRole
	MustChangePassword bool
}

const userColumns = `id, public_id, username, password_hash, role, enabled, must_change_password, created_at, updated_at`

func (s *Store) CreateUser(ctx context.Context, input CreateUserParams) (User, error) {
	input.Username = strings.TrimSpace(input.Username)
	if !usernamePattern.MatchString(input.Username) {
		return User{}, errors.New("username must contain 3 to 64 letters, numbers, dots, underscores, or hyphens")
	}
	if input.Role != RoleAdmin && input.Role != RoleUser {
		return User{}, errors.New("user role must be admin or user")
	}
	passwordHash, err := passwordauth.HashPassword(input.Password)
	if err != nil {
		return User{}, err
	}
	publicID, err := newPublicID("usr")
	if err != nil {
		return User{}, err
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (public_id, username, password_hash, role, must_change_password)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (username) DO NOTHING
		RETURNING `+userColumns,
		publicID, input.Username, passwordHash, input.Role, input.MustChangePassword)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return sanitizedUser(user), nil
}

func (s *Store) UserByPublicID(ctx context.Context, publicID string) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE public_id = ?", publicID))
	return sanitizedUser(user), err
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ?", strings.TrimSpace(username)))
	return sanitizedUser(user), err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userColumns+" FROM users ORDER BY username COLLATE NOCASE")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, sanitizedUser(user))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *Store) authenticateUser(ctx context.Context, username, password string) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ?", strings.TrimSpace(username)))
	if errors.Is(err, ErrUserNotFound) {
		_, _ = passwordauth.VerifyPassword(dummyPasswordHash, password)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, err
	}
	matched, err := passwordauth.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		return User{}, fmt.Errorf("verify stored password: %w", err)
	}
	if !matched || !user.Enabled {
		return User{}, ErrInvalidCredentials
	}
	return user, nil
}

func (s *Store) SetUserRole(ctx context.Context, publicID string, role UserRole) (User, error) {
	if role != RoleAdmin && role != RoleUser {
		return User{}, errors.New("user role must be admin or user")
	}
	return updateUser(s.db.QueryRowContext(ctx, `
		UPDATE users SET role = ?, updated_at = unixepoch() WHERE public_id = ? RETURNING `+userColumns,
		role, publicID))
}

func (s *Store) SetUserEnabled(ctx context.Context, publicID string, enabled bool) (User, error) {
	return updateUser(s.db.QueryRowContext(ctx, `
		UPDATE users SET enabled = ?, updated_at = unixepoch() WHERE public_id = ? RETURNING `+userColumns,
		enabled, publicID))
}

func (s *Store) ResetPassword(ctx context.Context, publicID, password string, mustChange bool) (User, error) {
	passwordHash, err := passwordauth.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	return updateUser(s.db.QueryRowContext(ctx, `
		UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = unixepoch()
		WHERE public_id = ? RETURNING `+userColumns,
		passwordHash, mustChange, publicID))
}

func (s *Store) ChangePassword(ctx context.Context, publicID, currentPassword, newPassword string) (User, error) {
	current, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE public_id = ?", publicID))
	if err != nil {
		return User{}, err
	}
	matched, err := passwordauth.VerifyPassword(current.PasswordHash, currentPassword)
	if err != nil {
		return User{}, fmt.Errorf("verify stored password: %w", err)
	}
	if !matched {
		return User{}, ErrInvalidCredentials
	}
	passwordHash, err := passwordauth.HashPassword(newPassword)
	if err != nil {
		return User{}, err
	}
	user, err := scanUser(s.db.QueryRowContext(ctx, `
		UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = unixepoch()
		WHERE public_id = ? AND password_hash = ? RETURNING `+userColumns,
		passwordHash, publicID, current.PasswordHash))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserChanged
	}
	if err != nil {
		return User{}, fmt.Errorf("change password: %w", err)
	}
	return sanitizedUser(user), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func storedUser(row rowScanner) (User, error) {
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	return user, nil
}

func updateUser(row rowScanner) (User, error) {
	user, err := storedUser(row)
	return sanitizedUser(user), err
}

func scanUser(row rowScanner) (User, error) {
	var user User
	var createdAt, updatedAt int64
	err := row.Scan(
		&user.ID, &user.PublicID, &user.Username, &user.PasswordHash, &user.Role, &user.Enabled,
		&user.MustChangePassword, &createdAt, &updatedAt,
	)
	user.CreatedAt = time.Unix(createdAt, 0).UTC()
	user.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return user, err
}

func sanitizedUser(user User) User {
	user.PasswordHash = ""
	return user
}
