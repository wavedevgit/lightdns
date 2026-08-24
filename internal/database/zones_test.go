package database

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestZoneRecordRepositoryAndSnapshot(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_zone_repo_admin", "repo-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_zone_repo_owner", "repo-owner", RoleUser)
	otherID := insertTestUser(t, store.db, "user_zone_repo_other", "repo-other", RoleUser)
	admin, _ := store.UserByID(t.Context(), adminID)
	owner, _ := store.UserByID(t.Context(), ownerID)
	other, _ := store.UserByID(t.Context(), otherID)

	zone, err := store.CreateZone(t.Context(), owner, owner.ID, "Example.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "example.test" || zone.Status != ZonePending || zone.Revision != 1 {
		t.Fatalf("created zone = %+v", zone)
	}
	if _, err := store.ZoneByPublicID(t.Context(), other, zone.PublicID); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("other user's zone error = %v", err)
	}
	if _, err := store.CreateRecord(t.Context(), owner, zone.PublicID, RecordInput{
		Name: "www.example.test.", Type: RecordA, Value: "not-an-address", TTL: 300,
	}); err == nil {
		t.Fatal("invalid record value was accepted")
	}
	record, err := store.CreateRecord(t.Context(), owner, zone.PublicID, RecordInput{
		Name: "www.example.test.", Type: RecordA, Value: "192.0.2.10", TTL: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateRecordAtRevision(t.Context(), owner, zone.PublicID, record.PublicID, RecordInput{
		Name: record.Name, Type: RecordA, Value: "192.0.2.11", TTL: 300,
	}, zone.Revision); !errors.Is(err, ErrZoneConflict) {
		t.Fatalf("stale record update error = %v", err)
	}
	if _, err := store.CreateRecord(t.Context(), owner, zone.PublicID, RecordInput{
		Name: "www.example.test.", Type: RecordCNAME, Value: "target.example.test.", TTL: 300,
	}); err == nil {
		t.Fatal("CNAME conflict was accepted")
	}
	zone, err = store.ZoneByPublicID(t.Context(), owner, zone.PublicID)
	if err != nil || zone.Revision != 2 {
		t.Fatalf("zone after record = %+v, err = %v", zone, err)
	}
	zone, err = store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneActive, "", zone.Revision)
	if err != nil || zone.Status != ZoneActive || zone.Revision != 3 {
		t.Fatalf("reviewed zone = %+v, err = %v", zone, err)
	}
	if _, err := store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneSuspended, "", 2); !errors.Is(err, ErrZoneConflict) {
		t.Fatalf("stale review error = %v", err)
	}

	snapshot, err := store.AuthoritativeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result := snapshot.Lookup(dns.Question{Name: record.Name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if !result.Managed || len(result.Answer) != 1 {
		t.Fatalf("snapshot result = %+v", result)
	}
	events, err := store.ListAuditEvents(t.Context(), admin, 0, 100)
	if err != nil || len(events) != 3 {
		t.Fatalf("audit events = %d, err = %v", len(events), err)
	}
	if _, err := store.ListAuditEvents(t.Context(), owner, 0, 100); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user audit error = %v", err)
	}
}

func TestZoneRepositoryScopesMutations(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_zone_scope_adm", "scope-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_zone_scope_own", "scope-owner", RoleUser)
	otherID := insertTestUser(t, store.db, "user_zone_scope_oth", "scope-other", RoleUser)
	owner, _ := store.UserByID(t.Context(), ownerID)
	other, _ := store.UserByID(t.Context(), otherID)
	zone, err := store.CreateZone(t.Context(), owner, owner.ID, "scope.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRecord(t.Context(), other, zone.PublicID, RecordInput{
		Name: "scope.test.", Type: RecordTXT, Value: "forbidden", TTL: 60,
	}); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("other user's record error = %v", err)
	}
	if err := store.DeleteZone(t.Context(), other, zone.PublicID); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("other user's delete error = %v", err)
	}
}
