package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	passwordauth "lightdns/internal/auth"
	"lightdns/internal/database"
)

type userView struct {
	ID                 string            `json:"id"`
	Username           string            `json:"username"`
	Email              string            `json:"email"`
	Role               database.UserRole `json:"role"`
	Enabled            bool              `json:"enabled"`
	MustChangePassword bool              `json:"must_change_password"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

type zoneView struct {
	ID              string              `json:"id"`
	OwnerID         string              `json:"owner_id"`
	Name            string              `json:"name"`
	Status          database.ZoneStatus `json:"status"`
	Revision        int64               `json:"revision"`
	RejectionReason *string             `json:"rejection_reason,omitempty"`
	AppealEmail     string              `json:"appeal_email,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

type recordView struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Type      database.RecordType `json:"type"`
	Value     string              `json:"value"`
	TTL       uint32              `json:"ttl"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

type auditView struct {
	ID         int64           `json:"id"`
	ActorID    string          `json:"actor_id,omitempty"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   *string         `json:"target_id,omitempty"`
	Details    json.RawMessage `json:"details"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (s *Server) registerManagementRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/users", s.adminOnly(s.listUsers))
	mux.HandleFunc("POST /api/users", s.adminOnly(s.createUser))
	mux.HandleFunc("GET /api/users/{userID}", s.adminOnly(s.getUser))
	mux.HandleFunc("PATCH /api/users/{userID}", s.adminOnly(s.updateUser))
	mux.HandleFunc("DELETE /api/users/{userID}", s.adminOnly(s.deleteUser))
	mux.HandleFunc("POST /api/users/{userID}/password-reset", s.adminOnly(s.resetUserPassword))
	mux.HandleFunc("GET /api/zones", s.authenticated(s.listZones))
	mux.HandleFunc("POST /api/zones", s.authenticated(s.createZone))
	mux.HandleFunc("GET /api/zones/{zoneID}", s.authenticated(s.getZone))
	mux.HandleFunc("DELETE /api/zones/{zoneID}", s.authenticated(s.deleteZone))
	mux.HandleFunc("POST /api/zones/{zoneID}/review", s.adminOnly(s.reviewZone))
	mux.HandleFunc("GET /api/zones/{zoneID}/records", s.authenticated(s.listRecords))
	mux.HandleFunc("POST /api/zones/{zoneID}/records", s.authenticated(s.createRecord))
	mux.HandleFunc("PUT /api/zones/{zoneID}/records/{recordID}", s.authenticated(s.updateRecord))
	mux.HandleFunc("DELETE /api/zones/{zoneID}/records/{recordID}", s.authenticated(s.deleteRecord))
	mux.HandleFunc("GET /api/audit", s.adminOnly(s.listAudit))
}

func (s *Server) listUsers(w http.ResponseWriter, request *http.Request) {
	users, err := s.database.ListUsers(request.Context())
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	result := make([]userView, 0, len(users))
	for _, user := range users {
		result = append(result, userResponse(user))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": result})
}

func (s *Server) createUser(w http.ResponseWriter, request *http.Request) {
	var input struct {
		Username           string            `json:"username"`
		Email              string            `json:"email"`
		Password           string            `json:"password"`
		Role               database.UserRole `json:"role"`
		MustChangePassword bool              `json:"must_change_password"`
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "User request is not valid JSON.")
		return
	}
	if strings.TrimSpace(input.Email) == "" {
		writeError(w, http.StatusBadRequest, "Email is required.")
		return
	}
	actor := currentPrincipal(request).User
	user, err := s.database.CreateUserAudited(request.Context(), actor, database.CreateUserParams{
		Username: input.Username, Email: input.Email, Password: input.Password, Role: input.Role, MustChangePassword: input.MustChangePassword,
	})
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, userResponse(user))
}

func (s *Server) getUser(w http.ResponseWriter, request *http.Request) {
	user, err := s.database.UserByPublicID(request.Context(), request.PathValue("userID"))
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userResponse(user))
}

func (s *Server) updateUser(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input struct {
		Username *string            `json:"username"`
		Email    *string            `json:"email"`
		Role     *database.UserRole `json:"role"`
		Enabled  *bool              `json:"enabled"`
	}
	if err := decodeJSON(request.Body, &input); err != nil || (input.Username == nil && input.Email == nil && input.Role == nil && input.Enabled == nil) {
		writeError(w, http.StatusBadRequest, "User update is not valid JSON.")
		return
	}
	publicID := request.PathValue("userID")
	actor := currentPrincipal(request).User
	user, err := s.database.UpdateUserAudited(request.Context(), actor, publicID, input.Username, input.Email, input.Role, input.Enabled)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userResponse(user))
}

func (s *Server) deleteUser(w http.ResponseWriter, request *http.Request) {
	publicID := request.PathValue("userID")
	actor := currentPrincipal(request).User
	err := s.database.DeleteUserAudited(request.Context(), actor, publicID)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input struct {
		Password           string `json:"password"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Password reset is not valid JSON.")
		return
	}
	publicID := request.PathValue("userID")
	actor := currentPrincipal(request).User
	user, err := s.database.ResetPasswordAudited(request.Context(), actor, publicID, input.Password, input.MustChangePassword)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userResponse(user))
}

func (s *Server) listZones(w http.ResponseWriter, request *http.Request) {
	actor := currentPrincipal(request).User
	zones, err := s.database.ListZones(request.Context(), actor)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	result := make([]zoneView, 0, len(zones))
	for _, zone := range zones {
		view, err := s.zoneResponse(request, zone)
		if err != nil {
			writeDatabaseError(w, err)
			return
		}
		result = append(result, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": result})
}

func (s *Server) createZone(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input struct {
		Name    string `json:"name"`
		OwnerID string `json:"owner_id"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Zone request is not valid JSON.")
		return
	}
	actor := currentPrincipal(request).User
	owner := actor
	if input.OwnerID != "" {
		if actor.Role != database.RoleAdmin && input.OwnerID != actor.PublicID {
			writeDatabaseError(w, database.ErrForbidden)
			return
		}
		var err error
		owner, err = s.database.UserByPublicID(request.Context(), input.OwnerID)
		if err != nil {
			writeDatabaseError(w, err)
			return
		}
	}
	configuredLimits := s.controller.Snapshot().EffectiveZoneLimits()
	limits := database.ZoneLimits{MaxTotal: configuredLimits.MaxTotalPerUser, MaxActive: configuredLimits.MaxActivePerUser, MaxRejected: configuredLimits.MaxRejectedPerUser}
	zone, err := s.database.CreateZoneWithLimits(request.Context(), actor, owner.ID, input.Name, limits)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	view, err := s.zoneResponse(request, zone)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) getZone(w http.ResponseWriter, request *http.Request) {
	zone, err := s.database.ZoneByPublicID(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"))
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	view, err := s.zoneResponse(request, zone)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) reviewZone(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input struct {
		Status   database.ZoneStatus `json:"status"`
		Reason   string              `json:"reason"`
		Revision int64               `json:"revision"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Zone review is not valid JSON.")
		return
	}
	configuredLimits := s.controller.Snapshot().EffectiveZoneLimits()
	limits := database.ZoneLimits{MaxTotal: configuredLimits.MaxTotalPerUser, MaxActive: configuredLimits.MaxActivePerUser, MaxRejected: configuredLimits.MaxRejectedPerUser}
	zone, err := s.database.ReviewZoneWithLimits(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"), input.Status, input.Reason, input.Revision, limits)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	if err := s.reloadZones(request.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Zone change was saved but is not yet active; reconciliation will retry.")
		return
	}
	view, err := s.zoneResponse(request, zone)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteZone(w http.ResponseWriter, request *http.Request) {
	if err := s.database.DeleteZone(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID")); err != nil {
		writeDatabaseError(w, err)
		return
	}
	if err := s.reloadZones(request.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Zone deletion was saved but is not yet active; reconciliation will retry.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRecords(w http.ResponseWriter, request *http.Request) {
	records, err := s.database.ListRecords(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"))
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	result := make([]recordView, 0, len(records))
	for _, record := range records {
		result = append(result, recordResponse(record))
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": result})
}

func (s *Server) createRecord(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input database.RecordInput
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Record request is not valid JSON.")
		return
	}
	revision, ok := requiredRevision(w, request)
	if !ok {
		return
	}
	record, err := s.database.CreateRecordAtRevision(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"), input, revision)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	if err := s.reloadZones(request.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Record change was saved but is not yet active; reconciliation will retry.")
		return
	}
	writeJSON(w, http.StatusCreated, recordResponse(record))
}

func (s *Server) updateRecord(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	var input database.RecordInput
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Record request is not valid JSON.")
		return
	}
	revision, ok := requiredRevision(w, request)
	if !ok {
		return
	}
	record, err := s.database.UpdateRecordAtRevision(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"), request.PathValue("recordID"), input, revision)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	if err := s.reloadZones(request.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Record change was saved but is not yet active; reconciliation will retry.")
		return
	}
	writeJSON(w, http.StatusOK, recordResponse(record))
}

func (s *Server) deleteRecord(w http.ResponseWriter, request *http.Request) {
	revision, ok := requiredRevision(w, request)
	if !ok {
		return
	}
	if err := s.database.DeleteRecordAtRevision(request.Context(), currentPrincipal(request).User, request.PathValue("zoneID"), request.PathValue("recordID"), revision); err != nil {
		writeDatabaseError(w, err)
		return
	}
	if err := s.reloadZones(request.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Record deletion was saved but is not yet active; reconciliation will retry.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, request *http.Request) {
	before, _ := strconv.ParseInt(request.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	events, err := s.database.ListAuditEvents(request.Context(), currentPrincipal(request).User, before, limit)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	result := make([]auditView, 0, len(events))
	for _, event := range events {
		view := auditView{
			ID: event.ID, Action: event.Action, TargetType: event.TargetType, TargetID: event.TargetID,
			Details: event.Details, CreatedAt: event.CreatedAt,
		}
		if event.ActorUserID != nil {
			user, err := s.database.UserByID(request.Context(), *event.ActorUserID)
			if err != nil {
				writeDatabaseError(w, err)
				return
			}
			view.ActorID = user.PublicID
		}
		result = append(result, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": result})
}

func (s *Server) zoneResponse(request *http.Request, zone database.Zone) (zoneView, error) {
	owner, err := s.database.UserByID(request.Context(), zone.OwnerID)
	if err != nil {
		return zoneView{}, err
	}
	return zoneView{
		ID: zone.PublicID, OwnerID: owner.PublicID, Name: zone.Name, Status: zone.Status, Revision: zone.Revision,
		RejectionReason: zone.RejectionReason, AppealEmail: s.controller.Snapshot().EffectiveZoneLimits().AppealEmail,
		CreatedAt: zone.CreatedAt, UpdatedAt: zone.UpdatedAt,
	}, nil
}

func userResponse(user database.User) userView {
	return userView{
		ID: user.PublicID, Username: user.Username, Email: user.Email, Role: user.Role, Enabled: user.Enabled,
		MustChangePassword: user.MustChangePassword, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}
}

func recordResponse(record database.DNSRecord) recordView {
	return recordView{
		ID: record.PublicID, Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}

func writeDatabaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "Invalid username or password.")
	case errors.Is(err, database.ErrForbidden):
		writeError(w, http.StatusForbidden, "Operation is not permitted.")
	case errors.Is(err, database.ErrUserNotFound), errors.Is(err, database.ErrZoneNotFound), errors.Is(err, database.ErrRecordNotFound), errors.Is(err, database.ErrSessionNotFound):
		writeError(w, http.StatusNotFound, "Resource was not found.")
	case errors.Is(err, database.ErrUsernameTaken), errors.Is(err, database.ErrZoneConflict), errors.Is(err, database.ErrUserChanged), strings.Contains(err.Error(), "constraint failed"):
		writeError(w, http.StatusConflict, "The requested change conflicts with existing data or a newer update.")
	case errors.Is(err, database.ErrZoneNotActive):
		writeError(w, http.StatusConflict, "Zone must be approved before records can be added.")
	case errors.Is(err, database.ErrZoneTotalLimit):
		writeError(w, http.StatusConflict, "This owner has reached the total managed zone limit.")
	case errors.Is(err, database.ErrZoneActiveLimit):
		writeError(w, http.StatusConflict, "This owner has reached the active managed zone limit.")
	case errors.Is(err, database.ErrZoneRejectedLimit):
		writeError(w, http.StatusConflict, "This owner has reached the rejected zone limit and cannot request another zone.")
	case errors.Is(err, database.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, passwordauth.ErrPasswordTooShort), errors.Is(err, passwordauth.ErrPasswordTooLong), errors.Is(err, passwordauth.ErrInvalidPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		slog.Error("management API database operation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "The request could not be completed.")
	}
}

func (s *Server) reloadZones(ctx context.Context) error {
	if err := s.controller.ReloadZones(ctx); err != nil {
		slog.Error("authoritative zone reload failed; reconciliation will retry", "error", err)
		return err
	}
	return nil
}
