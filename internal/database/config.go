package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"lightdns/internal/config"
)

const (
	configurationKey     = "lightdns.configuration"
	configurationVersion = 1
)

var ErrConfigConflict = errors.New("configuration changed since it was loaded")

type configEnvelope struct {
	Version int            `json:"version"`
	Config  *config.Config `json:"config"`
}

func (s *Store) SaveConfig(ctx context.Context, cfg config.Config, expectedRevision int64) (int64, error) {
	data, err := encodeConfig(cfg)
	if err != nil {
		return 0, err
	}
	return saveConfig(ctx, s.db, data, expectedRevision)
}

func (s *Store) SaveConfigAudited(ctx context.Context, cfg config.Config, expectedRevision int64, actor User) (int64, error) {
	if actor.Role != RoleAdmin {
		return 0, ErrForbidden
	}
	data, err := encodeConfig(cfg)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin configuration save: %w", err)
	}
	defer tx.Rollback()
	revision, err := saveConfig(ctx, tx, data, expectedRevision)
	if err != nil {
		return 0, err
	}
	if err := appendAudit(ctx, tx, actor.ID, "settings.update", "settings", configurationKey, map[string]any{"revision": revision}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit configuration save: %w", err)
	}
	return revision, nil
}

func encodeConfig(cfg config.Config) ([]byte, error) {
	cfg.Admin.Token = ""
	if err := cfg.ValidateSettings(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	data, err := json.Marshal(configEnvelope{Version: configurationVersion, Config: &cfg})
	if err != nil {
		return nil, fmt.Errorf("encode configuration: %w", err)
	}
	return data, nil
}

type configQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func saveConfig(ctx context.Context, queryer configQueryRower, data []byte, expectedRevision int64) (int64, error) {
	var err error
	var revision int64
	if expectedRevision == 0 {
		err = queryer.QueryRowContext(ctx, `
			INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO NOTHING
			RETURNING revision
		`, configurationKey, string(data)).Scan(&revision)
	} else {
		err = queryer.QueryRowContext(ctx, `
			UPDATE settings
			SET value = ?, updated_at = unixepoch(), revision = revision + 1
			WHERE key = ? AND revision = ?
			RETURNING revision
		`, string(data), configurationKey, expectedRevision).Scan(&revision)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrConfigConflict
	}
	if err != nil {
		return 0, fmt.Errorf("save configuration: %w", err)
	}
	return revision, nil
}

func (s *Store) LoadConfig(ctx context.Context) (config.Config, int64, bool, error) {
	var raw string
	var revision int64
	err := s.db.QueryRowContext(ctx, "SELECT value, revision FROM settings WHERE key = ?", configurationKey).Scan(&raw, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return config.Config{}, 0, false, nil
	}
	if err != nil {
		return config.Config{}, 0, false, fmt.Errorf("read stored configuration: %w", err)
	}
	if err := rejectDuplicateKeys([]byte(raw)); err != nil {
		return config.Config{}, revision, true, fmt.Errorf("decode stored configuration: %w", err)
	}

	var envelope *configEnvelope
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return config.Config{}, revision, true, fmt.Errorf("decode stored configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return config.Config{}, revision, true, fmt.Errorf("decode stored configuration: expected one JSON object")
	}
	if envelope == nil || envelope.Config == nil {
		return config.Config{}, revision, true, fmt.Errorf("decode stored configuration: configuration object is required")
	}
	if envelope.Version != configurationVersion {
		return config.Config{}, revision, true, fmt.Errorf("stored configuration version %d is not supported", envelope.Version)
	}
	if envelope.Config.Admin.Token != "" {
		return config.Config{}, revision, true, fmt.Errorf("stored configuration contains legacy authentication material")
	}
	normalized, err := json.Marshal(envelope)
	if err != nil {
		return config.Config{}, revision, true, fmt.Errorf("normalize stored configuration: %w", err)
	}
	var storedShape, normalizedShape any
	if err := json.Unmarshal([]byte(raw), &storedShape); err != nil {
		return config.Config{}, revision, true, fmt.Errorf("decode stored configuration shape: %w", err)
	}
	if err := json.Unmarshal(normalized, &normalizedShape); err != nil {
		return config.Config{}, revision, true, fmt.Errorf("decode normalized configuration shape: %w", err)
	}
	if !reflect.DeepEqual(storedShape, normalizedShape) {
		return config.Config{}, revision, true, fmt.Errorf("stored configuration does not match the version %d schema", configurationVersion)
	}

	cfg := *envelope.Config
	if err := cfg.ValidateSettings(); err != nil {
		return config.Config{}, revision, true, fmt.Errorf("validate stored configuration: %w", err)
	}
	cfg.Admin.Token = ""
	return cfg, revision, true, nil
}

func (s *Store) DiscardConfig(ctx context.Context, revision int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM settings WHERE key = ? AND revision = ?", configurationKey, revision)
	if err != nil {
		return fmt.Errorf("discard configuration: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("discard configuration: %w", err)
	}
	if count != 1 {
		return ErrConfigConflict
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
