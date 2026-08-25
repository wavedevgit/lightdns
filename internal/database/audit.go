package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *Store) RecordAuditEvent(ctx context.Context, actor User, action, targetType, targetID string, details any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit event: %w", err)
	}
	defer tx.Rollback()
	if err := appendAudit(ctx, tx, actor.ID, action, targetType, targetID, details); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit event: %w", err)
	}
	return nil
}

func (s *Store) ListAuditEvents(ctx context.Context, actor User, beforeID int64, limit int) ([]AuditEvent, error) {
	if actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	query := `SELECT id, actor_user_id, action, target_type, target_id, details, created_at FROM audit_events`
	var args []any
	if beforeID > 0 {
		query += " WHERE id < ?"
		args = append(args, beforeID)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var actorID sql.NullInt64
		var targetID sql.NullString
		var details string
		var createdAt int64
		if err := rows.Scan(&event.ID, &actorID, &event.Action, &event.TargetType, &targetID, &details, &createdAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if actorID.Valid {
			event.ActorUserID = &actorID.Int64
		}
		if targetID.Valid {
			event.TargetID = &targetID.String
		}
		event.Details = []byte(details)
		event.CreatedAt = time.Unix(createdAt, 0).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}
