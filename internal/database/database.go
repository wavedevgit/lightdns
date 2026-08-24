package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = 3

type Store struct {
	db *sql.DB
}

var migrations = [CurrentSchemaVersion][]string{
	{
		`CREATE TABLE settings (
			key TEXT PRIMARY KEY NOT NULL CHECK (length(key) > 0),
			value TEXT NOT NULL,
			updated_at INTEGER NOT NULL DEFAULT (unixepoch())
		) STRICT`,
	},
	{`ALTER TABLE settings ADD COLUMN revision INTEGER NOT NULL DEFAULT 1`},
	coreModelsMigration,
}

func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	query := url.Values{
		"_busy_timeout": {"5000"},
		"_defensive":    {"1"},
		"_foreign_keys": {"on"},
		"_journal_mode": {"WAL"},
		"_synchronous":  {"NORMAL"},
		"_txlock":       {"immediate"},
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolutePath), RawQuery: query.Encode()}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	closeOnError := func(err error) (*Store, error) {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return closeOnError(fmt.Errorf("connect to database: %w", err))
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return closeOnError(fmt.Errorf("read journal mode: %w", err))
	}
	if !strings.EqualFold(journalMode, "wal") {
		return closeOnError(fmt.Errorf("database does not support WAL mode: %s", journalMode))
	}
	if err := migrate(ctx, db); err != nil {
		return closeOnError(err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read setting %q: %w", key, err)
	}
	return value, true, nil
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("setting key is required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET
			value = excluded.value,
			updated_at = unixepoch(),
			revision = settings.revision + 1
	`, key, value)
	if err != nil {
		return fmt.Errorf("write setting %q: %w", key, err)
	}
	return nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL DEFAULT (unixepoch())
		) STRICT
	`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var latest int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&latest); err != nil {
		return fmt.Errorf("read latest migration: %w", err)
	}
	if latest > CurrentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", latest, CurrentSchemaVersion)
	}

	for index, statements := range migrations {
		version := index + 1
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)", version).Scan(&exists); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("finish migration check %d: %w", version, err)
			}
			continue
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				break
			}
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version)
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}
