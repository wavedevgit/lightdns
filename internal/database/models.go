package database

import (
	"encoding/json"
	"time"
)

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

type ZoneStatus string

const (
	ZonePending   ZoneStatus = "pending"
	ZoneActive    ZoneStatus = "active"
	ZoneRejected  ZoneStatus = "rejected"
	ZoneSuspended ZoneStatus = "suspended"
)

type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
	RecordMX    RecordType = "MX"
	RecordTXT   RecordType = "TXT"
	RecordNS    RecordType = "NS"
	RecordPTR   RecordType = "PTR"
	RecordSRV   RecordType = "SRV"
	RecordCAA   RecordType = "CAA"
)

type User struct {
	ID                 int64
	PublicID           string
	Username           string
	Email              string
	PasswordHash       string `json:"-"`
	Role               UserRole
	Enabled            bool
	MustChangePassword bool
	DeletedAt          *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Session struct {
	ID         int64
	UserID     int64
	TokenHash  []byte `json:"-"`
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

type Zone struct {
	ID              int64
	PublicID        string
	OwnerID         int64
	Name            string
	Status          ZoneStatus
	Revision        int64
	ReviewedBy      *int64
	ReviewedAt      *time.Time
	RejectionReason *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type DNSRecord struct {
	ID        int64
	PublicID  string
	ZoneID    int64
	Name      string
	Type      RecordType
	Value     string
	TTL       uint32
	CreatedAt time.Time
	UpdatedAt time.Time
}

type AuditEvent struct {
	ID          int64
	ActorUserID *int64
	Action      string
	TargetType  string
	TargetID    *string
	Details     json.RawMessage
	CreatedAt   time.Time
}

var coreModelsMigration = []string{
	`CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		public_id TEXT NOT NULL UNIQUE CHECK (length(public_id) BETWEEN 16 AND 64),
		username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (
			length(username) BETWEEN 1 AND 128 AND username = trim(username)
		),
		password_hash TEXT NOT NULL CHECK (
			length(password_hash) BETWEEN 20 AND 512 AND substr(password_hash, 1, 10) = '$argon2id$'
		),
		role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
		enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
		must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
		created_at INTEGER NOT NULL DEFAULT (unixepoch()),
		updated_at INTEGER NOT NULL DEFAULT (unixepoch())
	) STRICT`,
	`CREATE TABLE sessions (
		id INTEGER PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash BLOB NOT NULL UNIQUE CHECK (typeof(token_hash) = 'blob' AND length(token_hash) = 32),
		created_at INTEGER NOT NULL DEFAULT (unixepoch()),
		expires_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
		CHECK (expires_at > created_at)
	) STRICT`,
	`CREATE INDEX sessions_user_id ON sessions(user_id)`,
	`CREATE INDEX sessions_expires_at ON sessions(expires_at)`,
	`CREATE TABLE zones (
		id INTEGER PRIMARY KEY,
		public_id TEXT NOT NULL UNIQUE CHECK (length(public_id) BETWEEN 16 AND 64),
		owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
		name TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (
			length(name) BETWEEN 1 AND 253 AND name COLLATE BINARY = lower(name) AND name = trim(name) AND substr(name, -1) <> '.'
		),
		status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'rejected', 'suspended')),
		revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
		reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
		reviewed_at INTEGER,
		rejection_reason TEXT,
		created_at INTEGER NOT NULL DEFAULT (unixepoch()),
		updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
		CHECK (
			(status = 'pending' AND reviewed_by IS NULL AND reviewed_at IS NULL) OR
			(status <> 'pending' AND reviewed_at IS NOT NULL)
		),
		CHECK (
			(status = 'rejected' AND rejection_reason IS NOT NULL AND length(trim(rejection_reason)) > 0) OR
			(status <> 'rejected' AND rejection_reason IS NULL)
		)
	) STRICT`,
	`CREATE INDEX zones_owner_id ON zones(owner_id)`,
	`CREATE INDEX zones_status ON zones(status)`,
	`CREATE TABLE dns_records (
		id INTEGER PRIMARY KEY,
		public_id TEXT NOT NULL UNIQUE CHECK (length(public_id) BETWEEN 16 AND 64),
		zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		name TEXT NOT NULL CHECK (
			length(name) BETWEEN 2 AND 254 AND name COLLATE BINARY = lower(name) AND
			name = trim(name) AND substr(name, -1) = '.'
		),
		type TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'CAA')),
		value TEXT NOT NULL CHECK (length(trim(value)) > 0),
		ttl INTEGER NOT NULL CHECK (ttl BETWEEN 1 AND 4294967295),
		created_at INTEGER NOT NULL DEFAULT (unixepoch()),
		updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
		UNIQUE (zone_id, name, type, value)
	) STRICT`,
	`CREATE INDEX dns_records_lookup ON dns_records(zone_id, name, type)`,
	`CREATE TABLE audit_events (
		id INTEGER PRIMARY KEY,
		actor_user_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
		action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
		target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 64),
		target_id TEXT,
		details TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	) STRICT`,
	`CREATE INDEX audit_events_actor_user_id ON audit_events(actor_user_id)`,
	`CREATE INDEX audit_events_created_at ON audit_events(created_at)`,
	`CREATE TRIGGER require_first_admin
	BEFORE INSERT ON users
	WHEN NOT EXISTS (SELECT 1 FROM users) AND (NEW.role <> 'admin' OR NEW.enabled <> 1)
	BEGIN
		SELECT RAISE(ABORT, 'the first user must be an enabled admin');
	END`,
	`CREATE TRIGGER prevent_last_admin_delete
	BEFORE DELETE ON users
	WHEN OLD.role = 'admin' AND OLD.enabled = 1
		AND NOT EXISTS (SELECT 1 FROM users WHERE id <> OLD.id AND role = 'admin' AND enabled = 1)
	BEGIN
		SELECT RAISE(ABORT, 'at least one enabled admin is required');
	END`,
	`CREATE TRIGGER prevent_last_admin_disable
	BEFORE UPDATE OF role, enabled ON users
	WHEN OLD.role = 'admin' AND OLD.enabled = 1
		AND (NEW.role <> 'admin' OR NEW.enabled <> 1)
		AND NOT EXISTS (SELECT 1 FROM users WHERE id <> OLD.id AND role = 'admin' AND enabled = 1)
	BEGIN
		SELECT RAISE(ABORT, 'at least one enabled admin is required');
	END`,
	`CREATE TRIGGER revoke_sessions_after_user_security_change
	AFTER UPDATE OF password_hash, role, enabled, must_change_password ON users
	WHEN NEW.password_hash <> OLD.password_hash
		OR NEW.role <> OLD.role
		OR NEW.enabled <> OLD.enabled
		OR NEW.must_change_password <> OLD.must_change_password
	BEGIN
		DELETE FROM sessions WHERE user_id = NEW.id;
	END`,
	`CREATE TRIGGER validate_session_user_insert
	BEFORE INSERT ON sessions
	WHEN NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND enabled = 1)
	BEGIN
		SELECT RAISE(ABORT, 'session user must be enabled');
	END`,
	`CREATE TRIGGER validate_session_user_update
	BEFORE UPDATE OF user_id ON sessions
	WHEN NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND enabled = 1)
	BEGIN
		SELECT RAISE(ABORT, 'session user must be enabled');
	END`,
	`CREATE TRIGGER validate_zone_review_insert
	BEFORE INSERT ON zones
	WHEN NEW.status <> 'pending' AND NOT EXISTS (
		SELECT 1 FROM users WHERE id = NEW.reviewed_by AND role = 'admin' AND enabled = 1
	)
	BEGIN
		SELECT RAISE(ABORT, 'zone reviewer must be an enabled admin');
	END`,
	`CREATE TRIGGER validate_zone_review_status
	BEFORE UPDATE OF status ON zones
	WHEN NEW.status <> OLD.status AND NEW.status <> 'pending' AND NOT EXISTS (
		SELECT 1 FROM users WHERE id = NEW.reviewed_by AND role = 'admin' AND enabled = 1
	)
	BEGIN
		SELECT RAISE(ABORT, 'zone reviewer must be an enabled admin');
	END`,
	`CREATE TRIGGER validate_zone_reviewer
	BEFORE UPDATE OF reviewed_by ON zones
	WHEN NEW.reviewed_by IS NOT NULL AND NOT EXISTS (
		SELECT 1 FROM users WHERE id = NEW.reviewed_by AND role = 'admin' AND enabled = 1
	)
	BEGIN
		SELECT RAISE(ABORT, 'zone reviewer must be an enabled admin');
	END`,
	`CREATE TRIGGER validate_dns_record_insert
	BEFORE INSERT ON dns_records
	WHEN NOT EXISTS (
		SELECT 1 FROM zones
		WHERE id = NEW.zone_id AND (
			rtrim(NEW.name, '.') = name OR
			substr(rtrim(NEW.name, '.'), -(length(name) + 1)) = '.' || name
		)
	)
	BEGIN
		SELECT RAISE(ABORT, 'record name must be inside its zone');
	END`,
	`CREATE TRIGGER validate_dns_record_update
	BEFORE UPDATE OF zone_id, name ON dns_records
	WHEN NOT EXISTS (
		SELECT 1 FROM zones
		WHERE id = NEW.zone_id AND (
			rtrim(NEW.name, '.') = name OR
			substr(rtrim(NEW.name, '.'), -(length(name) + 1)) = '.' || name
		)
	)
	BEGIN
		SELECT RAISE(ABORT, 'record name must be inside its zone');
	END`,
	`CREATE TRIGGER prevent_dns_record_cname_conflict_insert
	BEFORE INSERT ON dns_records
	WHEN EXISTS (
		SELECT 1 FROM dns_records
		WHERE zone_id = NEW.zone_id AND name = NEW.name AND (NEW.type = 'CNAME' OR type = 'CNAME')
	)
	BEGIN
		SELECT RAISE(ABORT, 'CNAME cannot coexist with other records');
	END`,
	`CREATE TRIGGER prevent_dns_record_cname_conflict_update
	BEFORE UPDATE OF zone_id, name, type ON dns_records
	WHEN EXISTS (
		SELECT 1 FROM dns_records
		WHERE id <> OLD.id AND zone_id = NEW.zone_id AND name = NEW.name
			AND (NEW.type = 'CNAME' OR type = 'CNAME')
	)
	BEGIN
		SELECT RAISE(ABORT, 'CNAME cannot coexist with other records');
	END`,
	`CREATE TRIGGER dns_records_insert_revision
	AFTER INSERT ON dns_records
	BEGIN
		UPDATE zones SET revision = revision + 1, updated_at = unixepoch() WHERE id = NEW.zone_id;
	END`,
	`CREATE TRIGGER dns_records_update_revision
	AFTER UPDATE ON dns_records
	BEGIN
		UPDATE zones SET revision = revision + 1, updated_at = unixepoch() WHERE id = NEW.zone_id;
		UPDATE zones SET revision = revision + 1, updated_at = unixepoch() WHERE id = OLD.zone_id AND OLD.zone_id <> NEW.zone_id;
	END`,
	`CREATE TRIGGER dns_records_delete_revision
	AFTER DELETE ON dns_records
	BEGIN
		UPDATE zones SET revision = revision + 1, updated_at = unixepoch() WHERE id = OLD.zone_id;
	END`,
	`CREATE TRIGGER prevent_audit_event_update
	BEFORE UPDATE ON audit_events
	BEGIN
		SELECT RAISE(ABORT, 'audit events are append-only');
	END`,
	`CREATE TRIGGER prevent_audit_event_delete
	BEFORE DELETE ON audit_events
	BEGIN
		SELECT RAISE(ABORT, 'audit events are append-only');
	END`,
}
