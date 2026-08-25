package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
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
	Email              string
	Password           string
	Role               UserRole
	MustChangePassword bool
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

const userColumns = `id, public_id, username, email, password_hash, role, enabled, must_change_password, deleted_at, created_at, updated_at`

func (s *Store) CreateUser(ctx context.Context, input CreateUserParams) (User, error) {
	publicID, passwordHash, err := prepareUser(input)
	if err != nil {
		return User{}, err
	}
	user, err := insertUser(ctx, s.db, input, publicID, passwordHash)
	if err != nil {
		return User{}, err
	}
	return sanitizedUser(user), nil
}

func (s *Store) CreateUserAudited(ctx context.Context, actor User, input CreateUserParams) (User, error) {
	publicID, passwordHash, err := prepareUser(input)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user creation: %w", err)
	}
	defer tx.Rollback()
	user, err := insertUser(ctx, tx, input, publicID, passwordHash)
	if err != nil {
		return User{}, err
	}
	if err := appendAudit(ctx, tx, actor.ID, "user.create", "user", user.PublicID, map[string]any{"role": user.Role}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user creation: %w", err)
	}
	return sanitizedUser(user), nil
}

func prepareUser(input CreateUserParams) (string, string, error) {
	input.Username = strings.TrimSpace(input.Username)
	if !usernamePattern.MatchString(input.Username) {
		return "", "", fmt.Errorf("%w: username must contain 3 to 64 letters, numbers, dots, underscores, or hyphens", ErrInvalidInput)
	}
	if input.Role != RoleAdmin && input.Role != RoleUser {
		return "", "", fmt.Errorf("%w: user role must be admin or user", ErrInvalidInput)
	}
	if _, err := normalizeUserEmail(input.Username, input.Email); err != nil {
		return "", "", err
	}
	passwordHash, err := passwordauth.HashPassword(input.Password)
	if err != nil {
		return "", "", err
	}
	publicID, err := newPublicID("usr")
	if err != nil {
		return "", "", err
	}
	return publicID, passwordHash, nil
}

type userQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func insertUser(ctx context.Context, queryer userQueryer, input CreateUserParams, publicID, passwordHash string) (User, error) {
	input.Username = strings.TrimSpace(input.Username)
	input.Email, _ = normalizeUserEmail(input.Username, input.Email)
	row := queryer.QueryRowContext(ctx, `
		INSERT INTO users (public_id, username, email, password_hash, role, must_change_password)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (username) DO NOTHING
		RETURNING `+userColumns,
		publicID, input.Username, input.Email, passwordHash, input.Role, input.MustChangePassword)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func normalizeUserEmail(username, email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return strings.ToLower(strings.TrimSpace(username)) + "@local.invalid", nil
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 {
		return "", fmt.Errorf("%w: email address is not valid", ErrInvalidInput)
	}
	return email, nil
}

func (s *Store) UpdateUserAudited(ctx context.Context, actor User, publicID string, username, email *string, role *UserRole, enabled *bool) (User, error) {
	if username == nil && email == nil && role == nil && enabled == nil {
		return User{}, fmt.Errorf("%w: at least one user field is required", ErrInvalidInput)
	}
	if role != nil && *role != RoleAdmin && *role != RoleUser {
		return User{}, fmt.Errorf("%w: user role must be admin or user", ErrInvalidInput)
	}
	if username != nil {
		trimmed := strings.TrimSpace(*username)
		if !usernamePattern.MatchString(trimmed) {
			return User{}, fmt.Errorf("%w: username must contain 3 to 64 letters, numbers, dots, underscores, or hyphens", ErrInvalidInput)
		}
		username = &trimmed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user update: %w", err)
	}
	defer tx.Rollback()
	current, err := storedUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE public_id = ? AND deleted_at IS NULL", publicID))
	if err != nil {
		return User{}, err
	}
	effectiveUsername := current.Username
	var usernameValue, emailValue, roleValue, enabledValue any
	if username != nil {
		var taken bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND public_id <> ?)", *username, publicID).Scan(&taken); err != nil {
			return User{}, fmt.Errorf("check username availability: %w", err)
		}
		if taken {
			return User{}, ErrUsernameTaken
		}
		usernameValue = *username
		effectiveUsername = *username
	}
	if email != nil {
		normalized, err := normalizeUserEmail(effectiveUsername, *email)
		if err != nil {
			return User{}, err
		}
		emailValue = normalized
	}
	if role != nil {
		roleValue = *role
	}
	if enabled != nil {
		enabledValue = *enabled
	}
	user, err := storedUser(tx.QueryRowContext(ctx, `
		UPDATE users SET username = COALESCE(?, username), email = COALESCE(?, email),
			role = COALESCE(?, role), enabled = COALESCE(?, enabled), updated_at = unixepoch()
		WHERE public_id = ? AND deleted_at IS NULL RETURNING `+userColumns, usernameValue, emailValue, roleValue, enabledValue, publicID))
	if err != nil {
		return User{}, err
	}
	if err := appendAudit(ctx, tx, actor.ID, "user.update", "user", publicID, map[string]any{"username": username, "email": email, "role": role, "enabled": enabled}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user update: %w", err)
	}
	return sanitizedUser(user), nil
}

func (s *Store) DeleteUserAudited(ctx context.Context, actor User, publicID string) error {
	if actor.PublicID == publicID {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user deletion: %w", err)
	}
	defer tx.Rollback()
	user, err := storedUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE public_id = ? AND deleted_at IS NULL", publicID))
	if err != nil {
		return err
	}
	tombstone := "deleted-" + user.PublicID
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET username = ?, email = ?, role = 'user', enabled = 0,
			must_change_password = 0, deleted_at = unixepoch(), updated_at = unixepoch()
		WHERE id = ?
	`, tombstone, tombstone+"@local.invalid", user.ID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", user.ID); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}
	if err := appendAudit(ctx, tx, actor.ID, "user.delete", "user", publicID, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user deletion: %w", err)
	}
	return nil
}

func (s *Store) ResetPasswordAudited(ctx context.Context, actor User, publicID, password string, mustChange bool) (User, error) {
	passwordHash, err := passwordauth.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin password reset: %w", err)
	}
	defer tx.Rollback()
	user, err := storedUser(tx.QueryRowContext(ctx, `
		UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = unixepoch()
		WHERE public_id = ? RETURNING `+userColumns, passwordHash, mustChange, publicID))
	if err != nil {
		return User{}, err
	}
	if err := appendAudit(ctx, tx, actor.ID, "user.password_reset", "user", publicID, map[string]any{"must_change_password": mustChange}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit password reset: %w", err)
	}
	return sanitizedUser(user), nil
}

func (s *Store) UserByPublicID(ctx context.Context, publicID string) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE public_id = ? AND deleted_at IS NULL", publicID))
	return sanitizedUser(user), err
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", id))
	return sanitizedUser(user), err
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ? AND deleted_at IS NULL", strings.TrimSpace(username)))
	return sanitizedUser(user), err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userColumns+" FROM users WHERE deleted_at IS NULL ORDER BY username COLLATE NOCASE")
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
	user, err := storedUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ? AND deleted_at IS NULL", strings.TrimSpace(username)))
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
		return User{}, fmt.Errorf("%w: user role must be admin or user", ErrInvalidInput)
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
	return s.changePassword(ctx, publicID, currentPassword, newPassword, false)
}

func (s *Store) ChangePasswordAudited(ctx context.Context, publicID, currentPassword, newPassword string) (User, error) {
	return s.changePassword(ctx, publicID, currentPassword, newPassword, true)
}

func (s *Store) changePassword(ctx context.Context, publicID, currentPassword, newPassword string, audit bool) (User, error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin password change: %w", err)
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = unixepoch()
		WHERE public_id = ? AND password_hash = ? RETURNING `+userColumns,
		passwordHash, publicID, current.PasswordHash))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserChanged
	}
	if err != nil {
		return User{}, fmt.Errorf("change password: %w", err)
	}
	if audit {
		if err := appendAudit(ctx, tx, current.ID, "user.password_change", "user", current.PublicID, nil); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit password change: %w", err)
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
	var deletedAt sql.NullInt64
	var createdAt, updatedAt int64
	err := row.Scan(
		&user.ID, &user.PublicID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.Enabled,
		&user.MustChangePassword, &deletedAt, &createdAt, &updatedAt,
	)
	if deletedAt.Valid {
		value := time.Unix(deletedAt.Int64, 0).UTC()
		user.DeletedAt = &value
	}
	user.CreatedAt = time.Unix(createdAt, 0).UTC()
	user.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return user, err
}

func sanitizedUser(user User) User {
	user.PasswordHash = ""
	return user
}
