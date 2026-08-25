package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"lightdns/internal/authoritative"
	"lightdns/internal/records"
)

var (
	ErrForbidden         = errors.New("operation is not permitted")
	ErrInvalidInput      = errors.New("input is not valid")
	ErrZoneNotFound      = errors.New("zone not found")
	ErrRecordNotFound    = errors.New("record not found")
	ErrZoneConflict      = errors.New("zone changed since it was loaded")
	ErrZoneNotActive     = errors.New("zone must be approved before records can be added")
	ErrZoneTotalLimit    = errors.New("owner has reached the total managed zone limit")
	ErrZoneActiveLimit   = errors.New("owner has reached the active managed zone limit")
	ErrZoneRejectedLimit = errors.New("owner has reached the rejected managed zone limit")
)

type ZoneLimits struct {
	MaxTotal    int
	MaxActive   int
	MaxRejected int
}

type ZoneWithRecords struct {
	Zone    Zone
	Records []DNSRecord
}

type RecordInput struct {
	Name  string
	Type  RecordType
	Value string
	TTL   uint32
}

const zoneColumns = `z.id, z.public_id, z.owner_id, z.name, z.status, z.revision, z.reviewed_by, z.reviewed_at, COALESCE(z.review_reason, z.rejection_reason), z.created_at, z.updated_at`
const zoneReturningColumns = `id, public_id, owner_id, name, status, revision, reviewed_by, reviewed_at, COALESCE(review_reason, rejection_reason), created_at, updated_at`
const recordColumns = `r.id, r.public_id, r.zone_id, r.name, r.type, r.value, r.ttl, r.created_at, r.updated_at`

func (s *Store) CreateZone(ctx context.Context, actor User, ownerID int64, name string) (Zone, error) {
	return s.CreateZoneWithLimits(ctx, actor, ownerID, name, ZoneLimits{})
}

func (s *Store) CreateZoneWithLimits(ctx context.Context, actor User, ownerID int64, name string, limits ZoneLimits) (Zone, error) {
	s.zoneMu.Lock()
	defer s.zoneMu.Unlock()
	name, err := normalizeZoneName(name)
	if err != nil {
		return Zone{}, err
	}
	if actor.Role != RoleAdmin && actor.ID != ownerID {
		return Zone{}, ErrForbidden
	}
	publicID, err := newPublicID("zon")
	if err != nil {
		return Zone{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Zone{}, fmt.Errorf("begin zone creation: %w", err)
	}
	defer tx.Rollback()
	if limits.MaxTotal > 0 || limits.MaxRejected > 0 {
		var total, rejected int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END), 0)
			FROM zones WHERE owner_id = ?
		`, ownerID).Scan(&total, &rejected); err != nil {
			return Zone{}, fmt.Errorf("count owner zones: %w", err)
		}
		if limits.MaxTotal > 0 && total >= limits.MaxTotal {
			return Zone{}, ErrZoneTotalLimit
		}
		if limits.MaxRejected > 0 && rejected >= limits.MaxRejected {
			return Zone{}, ErrZoneRejectedLimit
		}
	}
	zone, err := scanZone(tx.QueryRowContext(ctx, `
		INSERT INTO zones (public_id, owner_id, name) VALUES (?, ?, ?)
		RETURNING `+zoneReturningColumns+`
	`, publicID, ownerID, name))
	if err != nil {
		return Zone{}, fmt.Errorf("create zone: %w", err)
	}
	if err := appendAudit(ctx, tx, actor.ID, "zone.create", "zone", zone.PublicID, map[string]any{"name": zone.Name, "owner_id": ownerID}); err != nil {
		return Zone{}, err
	}
	if err := tx.Commit(); err != nil {
		return Zone{}, fmt.Errorf("commit zone creation: %w", err)
	}
	return zone, nil
}

func (s *Store) ListZones(ctx context.Context, actor User) ([]Zone, error) {
	query := "SELECT " + zoneColumns + " FROM zones z"
	var args []any
	if actor.Role != RoleAdmin {
		query += " WHERE z.owner_id = ?"
		args = append(args, actor.ID)
	}
	query += " ORDER BY z.name"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	defer rows.Close()
	var zones []Zone
	for rows.Next() {
		zone, err := scanZone(rows)
		if err != nil {
			return nil, fmt.Errorf("scan zone: %w", err)
		}
		zones = append(zones, zone)
	}
	return zones, rows.Err()
}

func (s *Store) ZoneByPublicID(ctx context.Context, actor User, publicID string) (Zone, error) {
	query := "SELECT " + zoneColumns + " FROM zones z WHERE z.public_id = ?"
	args := []any{publicID}
	if actor.Role != RoleAdmin {
		query += " AND z.owner_id = ?"
		args = append(args, actor.ID)
	}
	zone, err := scanZone(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Zone{}, ErrZoneNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("read zone: %w", err)
	}
	return zone, nil
}

func (s *Store) ReviewZone(ctx context.Context, actor User, publicID string, status ZoneStatus, reason string, expectedRevision int64) (Zone, error) {
	return s.ReviewZoneWithLimits(ctx, actor, publicID, status, reason, expectedRevision, ZoneLimits{})
}

func (s *Store) ReviewZoneWithLimits(ctx context.Context, actor User, publicID string, status ZoneStatus, reason string, expectedRevision int64, limits ZoneLimits) (Zone, error) {
	s.zoneMu.Lock()
	defer s.zoneMu.Unlock()
	if actor.Role != RoleAdmin || !actor.Enabled {
		return Zone{}, ErrForbidden
	}
	if status != ZoneActive && status != ZoneRejected && status != ZoneSuspended {
		return Zone{}, fmt.Errorf("%w: review status must be active, rejected, or suspended", ErrInvalidInput)
	}
	reason = strings.TrimSpace(reason)
	if (status == ZoneRejected || status == ZoneSuspended) && reason == "" {
		return Zone{}, fmt.Errorf("%w: a reason is required when rejecting or suspending a zone", ErrInvalidInput)
	}
	if status == ZoneActive {
		reason = ""
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Zone{}, fmt.Errorf("begin zone review: %w", err)
	}
	defer tx.Rollback()
	if status == ZoneActive && limits.MaxActive > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM zones
			WHERE owner_id = (SELECT owner_id FROM zones WHERE public_id = ?)
				AND status = 'active' AND public_id <> ?
		`, publicID, publicID).Scan(&active); err != nil {
			return Zone{}, fmt.Errorf("count active owner zones: %w", err)
		}
		if active >= limits.MaxActive {
			return Zone{}, ErrZoneActiveLimit
		}
	}
	zone, err := scanZone(tx.QueryRowContext(ctx, `
		UPDATE zones SET status = ?, revision = revision + 1, reviewed_by = ?, reviewed_at = unixepoch(),
			rejection_reason = CASE WHEN ? = 'rejected' THEN NULLIF(?, '') ELSE NULL END,
			review_reason = CASE WHEN ? IN ('rejected', 'suspended') THEN NULLIF(?, '') ELSE NULL END,
			updated_at = unixepoch()
		WHERE public_id = ? AND revision = ?
		RETURNING `+zoneReturningColumns+`
	`, status, actor.ID, status, reason, status, reason, publicID, expectedRevision))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if queryErr := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE public_id = ?)", publicID).Scan(&exists); queryErr != nil {
			return Zone{}, fmt.Errorf("check zone review: %w", queryErr)
		}
		if exists {
			return Zone{}, ErrZoneConflict
		}
		return Zone{}, ErrZoneNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("review zone: %w", err)
	}
	if err := appendAudit(ctx, tx, actor.ID, "zone.review", "zone", zone.PublicID, map[string]any{"status": status, "reason": reason}); err != nil {
		return Zone{}, err
	}
	if err := tx.Commit(); err != nil {
		return Zone{}, fmt.Errorf("commit zone review: %w", err)
	}
	return zone, nil
}

func (s *Store) DeleteZone(ctx context.Context, actor User, publicID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin zone deletion: %w", err)
	}
	defer tx.Rollback()
	query := "DELETE FROM zones WHERE public_id = ?"
	args := []any{publicID}
	if actor.Role != RoleAdmin {
		query += " AND owner_id = ?"
		args = append(args, actor.ID)
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrZoneNotFound
	}
	if err := appendAudit(ctx, tx, actor.ID, "zone.delete", "zone", publicID, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit zone deletion: %w", err)
	}
	return nil
}

func (s *Store) ListRecords(ctx context.Context, actor User, zonePublicID string) ([]DNSRecord, error) {
	zone, err := s.ZoneByPublicID(ctx, actor, zonePublicID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+recordColumns+" FROM dns_records r WHERE r.zone_id = ? ORDER BY r.name, r.type, r.id", zone.ID)
	if err != nil {
		return nil, fmt.Errorf("list records: %w", err)
	}
	defer rows.Close()
	var values []DNSRecord
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		values = append(values, record)
	}
	return values, rows.Err()
}

func (s *Store) CreateRecord(ctx context.Context, actor User, zonePublicID string, input RecordInput) (DNSRecord, error) {
	return s.CreateRecordAtRevision(ctx, actor, zonePublicID, input, 0)
}

func (s *Store) CreateRecordAtRevision(ctx context.Context, actor User, zonePublicID string, input RecordInput, expectedRevision int64) (DNSRecord, error) {
	zone, err := s.ZoneByPublicID(ctx, actor, zonePublicID)
	if err != nil {
		return DNSRecord{}, err
	}
	if zone.Status != ZoneActive {
		return DNSRecord{}, ErrZoneNotActive
	}
	input, err = normalizeRecord(zone.Name, input)
	if err != nil {
		return DNSRecord{}, err
	}
	publicID, err := newPublicID("rec")
	if err != nil {
		return DNSRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("begin record creation: %w", err)
	}
	defer tx.Rollback()
	if err := checkZoneRevision(ctx, tx, zone.ID, expectedRevision); err != nil {
		return DNSRecord{}, err
	}
	record, err := scanRecord(tx.QueryRowContext(ctx, `
		INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)
		RETURNING id, public_id, zone_id, name, type, value, ttl, created_at, updated_at
	`, publicID, zone.ID, input.Name, input.Type, input.Value, input.TTL))
	if err != nil {
		return DNSRecord{}, fmt.Errorf("create record: %w", err)
	}
	if err := appendAudit(ctx, tx, actor.ID, "record.create", "record", record.PublicID, map[string]any{"zone_id": zone.PublicID, "name": record.Name, "type": record.Type}); err != nil {
		return DNSRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DNSRecord{}, fmt.Errorf("commit record creation: %w", err)
	}
	return record, nil
}

func (s *Store) UpdateRecord(ctx context.Context, actor User, zonePublicID, recordPublicID string, input RecordInput) (DNSRecord, error) {
	return s.UpdateRecordAtRevision(ctx, actor, zonePublicID, recordPublicID, input, 0)
}

func (s *Store) UpdateRecordAtRevision(ctx context.Context, actor User, zonePublicID, recordPublicID string, input RecordInput, expectedRevision int64) (DNSRecord, error) {
	zone, err := s.ZoneByPublicID(ctx, actor, zonePublicID)
	if err != nil {
		return DNSRecord{}, err
	}
	input, err = normalizeRecord(zone.Name, input)
	if err != nil {
		return DNSRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("begin record update: %w", err)
	}
	defer tx.Rollback()
	if err := checkZoneRevision(ctx, tx, zone.ID, expectedRevision); err != nil {
		return DNSRecord{}, err
	}
	record, err := scanRecord(tx.QueryRowContext(ctx, `
		UPDATE dns_records SET name = ?, type = ?, value = ?, ttl = ?, updated_at = unixepoch()
		WHERE public_id = ? AND zone_id = ?
		RETURNING id, public_id, zone_id, name, type, value, ttl, created_at, updated_at
	`, input.Name, input.Type, input.Value, input.TTL, recordPublicID, zone.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return DNSRecord{}, ErrRecordNotFound
	}
	if err != nil {
		return DNSRecord{}, fmt.Errorf("update record: %w", err)
	}
	if err := appendAudit(ctx, tx, actor.ID, "record.update", "record", record.PublicID, map[string]any{"zone_id": zone.PublicID}); err != nil {
		return DNSRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DNSRecord{}, fmt.Errorf("commit record update: %w", err)
	}
	return record, nil
}

func (s *Store) DeleteRecord(ctx context.Context, actor User, zonePublicID, recordPublicID string) error {
	return s.DeleteRecordAtRevision(ctx, actor, zonePublicID, recordPublicID, 0)
}

func (s *Store) DeleteRecordAtRevision(ctx context.Context, actor User, zonePublicID, recordPublicID string, expectedRevision int64) error {
	zone, err := s.ZoneByPublicID(ctx, actor, zonePublicID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin record deletion: %w", err)
	}
	defer tx.Rollback()
	if err := checkZoneRevision(ctx, tx, zone.ID, expectedRevision); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM dns_records WHERE public_id = ? AND zone_id = ?", recordPublicID, zone.ID)
	if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrRecordNotFound
	}
	if err := appendAudit(ctx, tx, actor.ID, "record.delete", "record", recordPublicID, map[string]any{"zone_id": zone.PublicID}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit record deletion: %w", err)
	}
	return nil
}

func checkZoneRevision(ctx context.Context, tx *sql.Tx, zoneID, expectedRevision int64) error {
	if expectedRevision <= 0 {
		return nil
	}
	result, err := tx.ExecContext(ctx, "UPDATE zones SET updated_at = updated_at WHERE id = ? AND revision = ?", zoneID, expectedRevision)
	if err != nil {
		return fmt.Errorf("check zone revision: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check zone revision: %w", err)
	}
	if count != 1 {
		return ErrZoneConflict
	}
	return nil
}

func (s *Store) LoadActiveZones(ctx context.Context) ([]ZoneWithRecords, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin active zone read: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT "+zoneColumns+" FROM zones z WHERE z.status = 'active' ORDER BY z.name")
	if err != nil {
		return nil, fmt.Errorf("read active zones: %w", err)
	}
	var result []ZoneWithRecords
	for rows.Next() {
		zone, err := scanZone(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan active zone: %w", err)
		}
		result = append(result, ZoneWithRecords{Zone: zone})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate active zones: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range result {
		recordRows, err := tx.QueryContext(ctx, "SELECT "+recordColumns+" FROM dns_records r WHERE r.zone_id = ? ORDER BY r.id", result[index].Zone.ID)
		if err != nil {
			return nil, fmt.Errorf("read active zone records: %w", err)
		}
		for recordRows.Next() {
			record, err := scanRecord(recordRows)
			if err != nil {
				recordRows.Close()
				return nil, fmt.Errorf("scan active zone record: %w", err)
			}
			result[index].Records = append(result[index].Records, record)
		}
		if err := recordRows.Err(); err != nil {
			recordRows.Close()
			return nil, fmt.Errorf("iterate active zone records: %w", err)
		}
		if err := recordRows.Close(); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("finish active zone read: %w", err)
	}
	return result, nil
}

func (s *Store) AuthoritativeSnapshot(ctx context.Context) (*authoritative.Snapshot, error) {
	zones, err := s.LoadActiveZones(ctx)
	if err != nil {
		return nil, err
	}
	input := make([]authoritative.ZoneInput, 0, len(zones))
	for _, value := range zones {
		zone := authoritative.ZoneInput{Name: value.Zone.Name, Revision: value.Zone.Revision}
		for _, record := range value.Records {
			zone.Records = append(zone.Records, records.Record{
				Name: record.Name, Type: string(record.Type), Value: record.Value, TTL: record.TTL,
			})
		}
		input = append(input, zone)
	}
	return authoritative.New(input)
}

func normalizeZoneName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if strings.Contains(name, "*") {
		return "", fmt.Errorf("%w: zone name cannot contain a wildcard", ErrInvalidInput)
	}
	if _, ok := dns.IsDomainName(name + "."); !ok || name == "" || len(name) > 253 {
		return "", fmt.Errorf("%w: zone name is not valid", ErrInvalidInput)
	}
	return name, nil
}

func normalizeRecord(zoneName string, input RecordInput) (RecordInput, error) {
	name := strings.ToLower(strings.TrimSpace(input.Name))
	apex := dns.Fqdn(zoneName)
	switch {
	case name == "@":
		input.Name = apex
	case name == "":
		return RecordInput{}, fmt.Errorf("%w: record subdomain is required", ErrInvalidInput)
	case strings.HasSuffix(name, "."):
		input.Name = dns.Fqdn(name)
	case dns.IsSubDomain(apex, dns.Fqdn(name)):
		// Preserve full names accepted by earlier API versions.
		input.Name = dns.Fqdn(name)
	default:
		input.Name = dns.Fqdn(name + "." + zoneName)
	}
	input.Type = RecordType(strings.ToUpper(strings.TrimSpace(string(input.Type))))
	input.Value = strings.TrimSpace(input.Value)
	if !dns.IsSubDomain(apex, input.Name) {
		return RecordInput{}, fmt.Errorf("%w: record name must be inside its zone", ErrInvalidInput)
	}
	if input.Name == apex && input.Type == RecordCNAME {
		return RecordInput{}, fmt.Errorf("%w: zone apex cannot be a CNAME", ErrInvalidInput)
	}
	if input.Name != apex && input.Type == RecordNS {
		return RecordInput{}, fmt.Errorf("%w: delegation NS records are not supported", ErrInvalidInput)
	}
	if _, err := records.Parse(records.Record{Name: input.Name, Type: string(input.Type), Value: input.Value, TTL: input.TTL}); err != nil {
		return RecordInput{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return input, nil
}

func scanZone(row rowScanner) (Zone, error) {
	var zone Zone
	var reviewedBy sql.NullInt64
	var reviewedAt sql.NullInt64
	var reason sql.NullString
	var createdAt, updatedAt int64
	err := row.Scan(&zone.ID, &zone.PublicID, &zone.OwnerID, &zone.Name, &zone.Status, &zone.Revision,
		&reviewedBy, &reviewedAt, &reason, &createdAt, &updatedAt)
	if reviewedBy.Valid {
		zone.ReviewedBy = &reviewedBy.Int64
	}
	if reviewedAt.Valid {
		value := time.Unix(reviewedAt.Int64, 0).UTC()
		zone.ReviewedAt = &value
	}
	if reason.Valid {
		zone.RejectionReason = &reason.String
	}
	zone.CreatedAt = time.Unix(createdAt, 0).UTC()
	zone.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return zone, err
}

func scanRecord(row rowScanner) (DNSRecord, error) {
	var record DNSRecord
	var ttl int64
	var createdAt, updatedAt int64
	err := row.Scan(&record.ID, &record.PublicID, &record.ZoneID, &record.Name, &record.Type, &record.Value, &ttl, &createdAt, &updatedAt)
	record.TTL = uint32(ttl)
	record.CreatedAt = time.Unix(createdAt, 0).UTC()
	record.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return record, err
}

func appendAudit(ctx context.Context, tx *sql.Tx, actorID int64, action, targetType, targetID string, details any) error {
	data := []byte("{}")
	var err error
	if details != nil {
		data, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("encode audit details: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (actor_user_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)
	`, actorID, action, targetType, targetID, string(data)); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}
