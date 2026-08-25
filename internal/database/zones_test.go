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
		Name: "www.example.test.", Type: RecordA, Value: "192.0.2.10", TTL: 300,
	}); !errors.Is(err, ErrZoneNotActive) {
		t.Fatalf("pending zone record error = %v", err)
	}
	zone, err = store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneActive, "", zone.Revision)
	if err != nil || zone.Status != ZoneActive || zone.Revision != 2 {
		t.Fatalf("reviewed zone = %+v, err = %v", zone, err)
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
	if err != nil || zone.Revision != 3 {
		t.Fatalf("zone after record = %+v, err = %v", zone, err)
	}
	if _, err := store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneSuspended, "policy violation", 2); !errors.Is(err, ErrZoneConflict) {
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

func TestNormalizeRecordSubdomains(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "@", want: "example.test."},
		{name: "www", want: "www.example.test."},
		{name: "api.internal", want: "api.internal.example.test."},
		{name: "legacy.example.test", want: "legacy.example.test."},
	}
	for _, test := range tests {
		record, err := normalizeRecord("example.test", RecordInput{Name: test.name, Type: RecordA, Value: "192.0.2.10", TTL: 300})
		if err != nil {
			t.Fatalf("normalize %q: %v", test.name, err)
		}
		if record.Name != test.want {
			t.Fatalf("normalize %q = %q, want %q", test.name, record.Name, test.want)
		}
	}
}

func TestZoneLimitsPerOwner(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_zone_limit_admin", "limit-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_zone_limit_owner", "limit-owner", RoleUser)
	admin, _ := store.UserByID(t.Context(), adminID)
	owner, _ := store.UserByID(t.Context(), ownerID)
	limits := ZoneLimits{MaxTotal: 2, MaxActive: 1, MaxRejected: 1}

	rejected, err := store.CreateZoneWithLimits(t.Context(), owner, owner.ID, "rejected.test", limits)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err = store.ReviewZoneWithLimits(t.Context(), admin, rejected.PublicID, ZoneRejected, "not allowed", rejected.Revision, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateZoneWithLimits(t.Context(), owner, owner.ID, "blocked-by-rejections.test", limits); !errors.Is(err, ErrZoneRejectedLimit) {
		t.Fatalf("rejected zone limit error = %v", err)
	}
	if err := store.DeleteZone(t.Context(), owner, rejected.PublicID); err != nil {
		t.Fatal(err)
	}

	active, err := store.CreateZoneWithLimits(t.Context(), owner, owner.ID, "active.test", limits)
	if err != nil {
		t.Fatal(err)
	}
	active, err = store.ReviewZoneWithLimits(t.Context(), admin, active.PublicID, ZoneActive, "", active.Revision, limits)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.CreateZoneWithLimits(t.Context(), owner, owner.ID, "pending.test", limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateZoneWithLimits(t.Context(), owner, owner.ID, "over-total.test", limits); !errors.Is(err, ErrZoneTotalLimit) {
		t.Fatalf("total zone limit error = %v", err)
	}
	if _, err := store.ReviewZoneWithLimits(t.Context(), admin, pending.PublicID, ZoneActive, "", pending.Revision, limits); !errors.Is(err, ErrZoneActiveLimit) {
		t.Fatalf("active zone limit error = %v", err)
	}
}

func TestSuspendedZoneReason(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_zone_suspend_admin", "suspend-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_zone_suspend_owner", "suspend-owner", RoleUser)
	admin, _ := store.UserByID(t.Context(), adminID)
	owner, _ := store.UserByID(t.Context(), ownerID)
	zone, err := store.CreateZone(t.Context(), owner, owner.ID, "suspended.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneSuspended, "", zone.Revision); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty suspension reason error = %v", err)
	}
	zone, err = store.ReviewZone(t.Context(), admin, zone.PublicID, ZoneSuspended, "Repeated policy violations", zone.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if zone.RejectionReason == nil || *zone.RejectionReason != "Repeated policy violations" {
		t.Fatalf("suspension reason = %#v", zone.RejectionReason)
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
