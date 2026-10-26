package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

type defaultPrivilegeCursor struct {
	Version      int       `json:"v"`
	Purpose      string    `json:"purpose"`
	AccountID    uuid.UUID `json:"account_id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	Snapshot     string    `json:"snapshot"`
	QueryHash    string    `json:"query_hash"`
	Offset       int       `json:"offset"`
}

type defaultPrivilegeListResponse struct {
	Rules           []map[string]any    `json:"rules"`
	TotalEntries    *int                `json:"total_entries"`
	NextCursor      string              `json:"next_cursor"`
	SnapshotVersion string              `json:"snapshot_version"`
	Available       bool                `json:"available"`
	Inventory       *inventoryFreshness `json:"inventory"`
}

func defaultPrivilegeQueryHash(query string) string {
	sum := sha256.Sum256([]byte(query))
	return hex.EncodeToString(sum[:])
}

func defaultPrivilegePageParameters(w http.ResponseWriter, r *http.Request, accountID, connectionID uuid.UUID, snapshot string) (int, string, int, bool) {
	limit := 8
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 50 {
			respondError(w, http.StatusBadRequest, "limit must be between 1 and 50")
			return 0, "", 0, false
		}
		limit = value
	}
	query := r.URL.Query().Get("q")
	if len(query) > 256 || !utf8.ValidString(query) {
		respondError(w, http.StatusBadRequest, "query must be valid UTF-8 and at most 256 bytes")
		return 0, "", 0, false
	}
	offset := 0
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			respondError(w, http.StatusBadRequest, "invalid cursor")
			return 0, "", 0, false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		var cursor defaultPrivilegeCursor
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&cursor) != nil || decoder.Decode(new(any)) != io.EOF ||
			cursor.Version != 1 || cursor.Purpose != "defaults" || cursor.AccountID != accountID ||
			cursor.ConnectionID != connectionID || cursor.QueryHash != defaultPrivilegeQueryHash(query) || cursor.Offset <= 0 || cursor.Snapshot == "" {
			respondError(w, http.StatusBadRequest, "invalid cursor")
			return 0, "", 0, false
		}
		if cursor.Snapshot != snapshot {
			respondError(w, http.StatusConflict, "inventory_snapshot_changed: reload the first page")
			return 0, "", 0, false
		}
		offset = cursor.Offset
	}
	return limit, query, offset, true
}

func encodeDefaultPrivilegeCursor(accountID, connectionID uuid.UUID, snapshot, query string, offset int) string {
	raw, _ := json.Marshal(defaultPrivilegeCursor{
		Version: 1, Purpose: "defaults", AccountID: accountID, ConnectionID: connectionID,
		Snapshot: snapshot, QueryHash: defaultPrivilegeQueryHash(query), Offset: offset,
	})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeDefaultPrivilegeRule(raw map[string]json.RawMessage) (map[string]any, bool) {
	rule := make(map[string]any, 7)
	for _, field := range []string{"database", "creator", "schema", "kind", "grantee", "privilege"} {
		var value *string
		if json.Unmarshal(raw[field], &value) != nil || value == nil || !utf8.ValidString(*value) ||
			len(*value) > 63 || strings.ContainsRune(*value, 0) || (field != "schema" && *value == "") {
			return nil, false
		}
		rule[field] = *value
	}
	var grantOption *bool
	if json.Unmarshal(raw["grant_option"], &grantOption) != nil || grantOption == nil {
		return nil, false
	}
	rule["grant_option"] = *grantOption
	return rule, true
}

func defaultPrivilegePage(topology json.RawMessage, grantee, query string, offset, limit int) ([]map[string]any, int, bool) {
	page := make([]map[string]any, 0, limit)
	var document struct {
		Version int             `json:"postgres_object_acl_version"`
		Rules   json.RawMessage `json:"postgres_default_privileges"`
	}
	if json.Unmarshal(topology, &document) != nil || document.Version != 1 {
		return page, 0, false
	}
	decoder := json.NewDecoder(bytes.NewReader(document.Rules))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('[') {
		return page, 0, false
	}
	query = strings.ToLower(query)
	total := 0
	// Scan the snapshot to count matches, retaining only the requested page.
	// Missing or malformed evidence cannot be presented as an empty result.
	for decoder.More() {
		var raw map[string]json.RawMessage
		if decoder.Decode(&raw) != nil {
			return []map[string]any{}, 0, false
		}
		rule, valid := decodeDefaultPrivilegeRule(raw)
		if !valid {
			return []map[string]any{}, 0, false
		}
		if rule["grantee"] == "PUBLIC" || rule["grantee"] != grantee {
			continue
		}
		text := make([]string, 0, 6)
		for _, field := range []string{"database", "creator", "schema", "kind", "grantee", "privilege"} {
			text = append(text, rule[field].(string))
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join(text, " ")), query) {
			continue
		}
		if total >= offset && len(page) < limit {
			page = append(page, rule)
		}
		total++
	}
	if last, err := decoder.Token(); err != nil || last != json.Delim(']') || decoder.Decode(new(any)) != io.EOF {
		return []map[string]any{}, 0, false
	}
	return page, total, true
}

func (s *Server) listAccountDefaultPrivileges(w http.ResponseWriter, r *http.Request) {
	accountID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	account, err := s.inventory.GetAccount(ctx, tx, accountID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	connection, err := s.connections.Get(ctx, tx, account.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScope(ctx, sess, connection.Environment)) {
		return
	}
	if connection.Engine != "postgres" {
		respondError(w, http.StatusBadRequest, "PostgreSQL connection required")
		return
	}
	snapshot := objectSnapshotVersion(connection, time.Unix(0, 0))
	limit, query, offset, ok := defaultPrivilegePageParameters(w, r, accountID, connection.ID, snapshot)
	if !ok {
		return
	}
	rules, total, available := defaultPrivilegePage(connection.Topology, account.EngineIdentity, query, offset, limit)
	if available && offset > total {
		respondError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	policies, err := rolepolicies.NewStore().List(ctx, tx, connection.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	freshness, err := inventoryFreshnessForSnapshot(ctx, tx, connection, policies)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	response := defaultPrivilegeListResponse{
		Rules: rules, Available: available, SnapshotVersion: snapshot,
		Inventory: freshness,
	}
	if available {
		response.TotalEntries = &total
		if next := offset + len(rules); next < total {
			response.NextCursor = encodeDefaultPrivilegeCursor(accountID, connection.ID, snapshot, query, next)
		}
	}
	respondJSON(w, http.StatusOK, response)
}
