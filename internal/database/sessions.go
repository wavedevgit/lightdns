package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type CreatedSession struct {
	Session Session
	User    User
	Token   string
}

type AuthenticatedSession struct {
	Session Session
	User    User
}

func (s *Store) CreateAuthenticatedSession(ctx context.Context, username, password string, lifetime time.Duration) (CreatedSession, error) {
	user, err := s.authenticateUser(ctx, username, password)
	if err != nil {
		return CreatedSession{}, err
	}
	return s.createSession(ctx, user, lifetime)
}

func (s *Store) createSession(ctx context.Context, user User, lifetime time.Duration) (CreatedSession, error) {
	if lifetime <= 0 {
		return CreatedSession{}, errors.New("session lifetime must be positive")
	}
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return CreatedSession{}, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(lifetime)
	if expiresAt.Unix() <= now.Unix() {
		return CreatedSession{}, errors.New("session lifetime must be at least one second")
	}
	var session Session
	var createdUnix, expiresUnix, lastSeenUnix int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, created_at, expires_at, last_seen_at)
		SELECT id, ?, ?, ?, ? FROM users
		WHERE id = ? AND password_hash = ? AND role = ? AND enabled = 1 AND must_change_password = ?
		RETURNING id, user_id, created_at, expires_at, last_seen_at
	`, tokenHash[:], now.Unix(), expiresAt.Unix(), now.Unix(), user.ID, user.PasswordHash, user.Role, user.MustChangePassword).Scan(
		&session.ID, &session.UserID, &createdUnix, &expiresUnix, &lastSeenUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CreatedSession{}, ErrInvalidCredentials
	}
	if err != nil {
		return CreatedSession{}, fmt.Errorf("create session: %w", err)
	}
	session.CreatedAt = time.Unix(createdUnix, 0).UTC()
	session.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	session.LastSeenAt = time.Unix(lastSeenUnix, 0).UTC()
	return CreatedSession{Session: session, User: sanitizedUser(user), Token: token}, nil
}

func (s *Store) SessionByToken(ctx context.Context, token string) (AuthenticatedSession, error) {
	tokenHash, ok := hashSessionToken(token)
	if !ok {
		return AuthenticatedSession{}, ErrSessionNotFound
	}
	var result AuthenticatedSession
	var sessionCreated, expiresAt, lastSeenAt, userCreated, userUpdated int64
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.created_at, s.expires_at, s.last_seen_at,
			u.id, u.public_id, u.username, u.role, u.enabled, u.must_change_password, u.created_at, u.updated_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > unixepoch() AND u.enabled = 1
	`, tokenHash[:]).Scan(
		&result.Session.ID, &result.Session.UserID, &sessionCreated, &expiresAt, &lastSeenAt,
		&result.User.ID, &result.User.PublicID, &result.User.Username, &result.User.Role,
		&result.User.Enabled, &result.User.MustChangePassword, &userCreated, &userUpdated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedSession{}, ErrSessionNotFound
	}
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("read session: %w", err)
	}
	result.Session.CreatedAt = time.Unix(sessionCreated, 0).UTC()
	result.Session.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	result.Session.LastSeenAt = time.Unix(lastSeenAt, 0).UTC()
	result.User.CreatedAt = time.Unix(userCreated, 0).UTC()
	result.User.UpdatedAt = time.Unix(userUpdated, 0).UTC()
	return result, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	tokenHash, ok := hashSessionToken(token)
	if !ok {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", tokenHash[:]); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}
	return nil
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= unixepoch()")
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count purged sessions: %w", err)
	}
	return count, nil
}

func hashSessionToken(token string) ([32]byte, bool) {
	rawToken, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(rawToken) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(rawToken), true
}
