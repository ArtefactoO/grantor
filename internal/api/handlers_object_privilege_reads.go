package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

type objectPrivilegeCursor struct {
	Version  int                          `json:"v"`
	Subject  uuid.UUID                    `json:"subject"`
	Snapshot string                       `json:"snapshot"`
	Query    string                       `json:"q"`
	After    inventory.ObjectPrivilegeKey `json:"after"`
}

type objectPrivilegeGroupJSON struct {
	Key                       string           `json:"key"`
	Resource                  string           `json:"resource"`
	ScopeID                   uuid.UUID        `json:"scope_id"`
	Kind                      string           `json:"kind"`
	Owner                     string           `json:"owner"`
	PublicPrivileges          []string         `json:"public_privileges"`
	PublicPrivilegesTruncated bool             `json:"public_privileges_truncated"`
	Permissions               []permissionJSON `json:"permissions"`
	Bindings                  []bindingJSON    `json:"bindings"`
}

func boundedObjectPublicPrivileges(raw any, kind, column string) ([]string, bool) {
	const maxPublicPrivileges = 30
	if column != "" {
		kind = "column"
	}
	allowed := adapter.PostgresObjectPrivileges(kind)
	out := []string{}
	rights, ok := raw.([]any)
	if raw == nil {
		return out, false
	}
	if !ok {
		return out, true
	}
	truncated := false
	seen := map[string]bool{}
	for _, value := range rights {
		text, ok := value.(string)
		if !ok {
			truncated = true
			continue
		}
		if column != "" {
			text = strings.TrimSuffix(text, " ("+column+")")
		}
		if len(text) > 32 || !slices.Contains(allowed, text) {
			truncated = true
			continue
		}
		if seen[text] {
			continue
		}
		if len(out) >= maxPublicPrivileges {
			truncated = true
			continue
		}
		seen[text] = true
		out = append(out, text)
	}
	slices.Sort(out)
	return out, truncated
}

func compactPostgresTopology(raw json.RawMessage) json.RawMessage {
	var data map[string]json.RawMessage
	if json.Unmarshal(raw, &data) != nil {
		return raw
	}
	delete(data, "hba_rules")
	delete(data, "postgres_default_privileges")
	delete(data, "postgres_access_evidence")
	out, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	return out
}

func objectPageParameters(w http.ResponseWriter, r *http.Request, subject uuid.UUID, snapshot string) (int, string, inventory.ObjectPrivilegeKey, bool) {
	limit := 8
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 50 {
			respondError(w, http.StatusBadRequest, "limit must be between 1 and 50")
			return 0, "", inventory.ObjectPrivilegeKey{}, false
		}
		limit = n
	}
	query := r.URL.Query().Get("q")
	if len(query) > 256 {
		respondError(w, http.StatusBadRequest, "query is too long")
		return 0, "", inventory.ObjectPrivilegeKey{}, false
	}
	var after inventory.ObjectPrivilegeKey
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			respondError(w, http.StatusBadRequest, "invalid cursor")
			return 0, "", after, false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		var c objectPrivilegeCursor
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&c) != nil || decoder.Decode(&struct{}{}) != io.EOF || c.Version != 1 || c.Subject != subject || c.Query != query || c.After.ScopeID == uuid.Nil || len(c.After.Label) > 512 || len(c.After.Column) > 63 {
			respondError(w, http.StatusBadRequest, "invalid cursor")
			return 0, "", after, false
		}
		if c.Snapshot != snapshot {
			respondError(w, http.StatusConflict, "inventory_snapshot_changed: reload the first page")
			return 0, "", after, false
		}
		after = c.After
	}
	return limit, query, after, true
}

func objectPageCursor(subject uuid.UUID, snapshot, query string, after inventory.ObjectPrivilegeKey) string {
	raw, _ := json.Marshal(objectPrivilegeCursor{Version: 1, Subject: subject, Snapshot: snapshot, Query: query, After: after})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func objectSnapshotVersion(c connections.Connection, revision time.Time) string {
	stamp := "unobserved"
	if c.LastDiscoveryAt != nil {
		stamp = c.LastDiscoveryAt.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%s:%d:%s", stamp, revision.UnixMicro(), connections.ConfigIncarnation(c))
}

func (s *Server) listAccountObjectPrivileges(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	a, err := s.inventory.GetAccount(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, a.ConnectionID)) {
		return
	}
	c, err := s.connections.Get(ctx, tx, a.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if c.Engine != "postgres" {
		respondError(w, http.StatusBadRequest, "PostgreSQL connection required")
		return
	}
	revision, err := s.inventory.ObjectPrivilegeRevision(ctx, tx, a.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	snapshot := objectSnapshotVersion(c, revision)
	limit, query, after, ok := objectPageParameters(w, r, id, snapshot)
	if !ok {
		return
	}
	var keys []inventory.ObjectPrivilegeKey
	total := 0
	if raw := r.URL.Query().Get("scope_resource_id"); raw != "" {
		if r.URL.Query().Get("cursor") != "" {
			respondError(w, http.StatusBadRequest, "scope selection does not accept a page cursor")
			return
		}
		scope, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			respondError(w, http.StatusBadRequest, "invalid scope_resource_id")
			return
		}
		resource, getErr := s.inventory.GetResource(ctx, tx, scope)
		if getErr != nil {
			respondStoreError(ctx, w, getErr)
			return
		}
		if resource.ConnectionID != a.ConnectionID {
			respondError(w, http.StatusNotFound, "object not found")
			return
		}
		keys = []inventory.ObjectPrivilegeKey{{ScopeID: scope, Label: resource.CanonicalPath}}
		total = 1
	} else {
		keys, total, err = s.inventory.ListObjectPrivilegeKeys(ctx, tx, id, a.ConnectionID, query, after, limit)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	next := ""
	if len(keys) > limit {
		keys = keys[:limit]
		next = objectPageCursor(id, snapshot, query, keys[len(keys)-1])
	}
	definitions, err := s.inventory.ObjectPrivilegeDefinitions(ctx, tx, a.ID, a.ConnectionID, keys)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	bindings, err := s.inventory.BindingsForDefinitions(ctx, tx, id, definitions)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	byPermission := map[uuid.UUID][]bindingJSON{}
	for _, b := range bindings {
		byPermission[b.PermissionDefinitionID] = append(byPermission[b.PermissionDefinitionID], toBindingJSON(b))
	}
	groups := []objectPrivilegeGroupJSON{}
	resourcesByID := map[uuid.UUID]inventory.Resource{}
	for _, key := range keys {
		resource, cached := resourcesByID[key.ScopeID]
		if !cached {
			var getErr error
			resource, getErr = s.inventory.GetResource(ctx, tx, key.ScopeID)
			if getErr != nil {
				respondStoreError(ctx, w, getErr)
				return
			}
			resourcesByID[key.ScopeID] = resource
		}
		attrs := decodeAttributes(resource.Attributes)
		owner, _ := attrs["owner"].(string)
		public, truncated := boundedObjectPublicPrivileges(attrs["public_privileges"], resource.Kind, key.Column)
		group := objectPrivilegeGroupJSON{Key: key.ScopeID.String() + ":" + key.Column, Resource: key.Label, ScopeID: key.ScopeID, Kind: resource.Kind, Owner: owner, PublicPrivileges: public, PublicPrivilegesTruncated: truncated, Permissions: []permissionJSON{}, Bindings: []bindingJSON{}}
		if key.Column != "" {
			group.Kind = "column"
		}
		for _, p := range definitions {
			column, _ := decodeAttributes(p.Attributes)["column"].(string)
			if p.ScopeResourceID == nil || *p.ScopeResourceID != key.ScopeID || column != key.Column {
				continue
			}
			projected := toPermissionJSON(p, map[uuid.UUID]string{key.ScopeID: resource.Name})
			if p.Status == "missing" {
				projected.Assignable = false
			}
			group.Permissions = append(group.Permissions, projected)
			group.Bindings = append(group.Bindings, byPermission[p.ID]...)
			if len(group.Permissions) == 1 {
				group.Resource = projected.Normalized.Resource
			}
		}
		if len(group.Permissions) > 0 {
			groups = append(groups, group)
		}
	}
	var topology struct {
		Version int `json:"postgres_object_acl_version"`
	}
	_ = json.Unmarshal(c.Topology, &topology)
	if r.URL.Query().Get("scope_resource_id") != "" {
		total = len(groups)
	}
	policies, err := rolepolicies.NewStore().List(ctx, tx, a.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	freshness, err := inventoryFreshnessForSnapshot(ctx, tx, c, policies)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"objects": groups, "total_entries": total, "next_cursor": next, "snapshot_version": snapshot, "available": topology.Version == 1, "inventory": freshness})
}

func (s *Server) listObjectPrivilegeTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireConnection(w, r)
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
	c, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if c.Engine != "postgres" {
		respondError(w, http.StatusBadRequest, "PostgreSQL connection required")
		return
	}
	snapshot := objectSnapshotVersion(c, time.Unix(0, 0))
	limit, query, after, ok := objectPageParameters(w, r, id, snapshot)
	if !ok {
		return
	}
	resources, err := s.inventory.ListObjectPrivilegeTargets(ctx, tx, id, query, after.Label, after.ScopeID, limit)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	next := ""
	if len(resources) > limit {
		resources = resources[:limit]
		last := resources[len(resources)-1]
		next = objectPageCursor(id, snapshot, query, inventory.ObjectPrivilegeKey{ScopeID: last.ID, Label: last.CanonicalPath})
	}
	objects := []map[string]any{}
	for _, res := range resources {
		attrs := decodeAttributes(res.Attributes)
		objects = append(objects, map[string]any{"scope_id": res.ID, "resource": res.CanonicalPath, "kind": res.Kind, "owner": attrs["owner"]})
	}
	respondJSON(w, http.StatusOK, map[string]any{"objects": objects, "next_cursor": next, "snapshot_version": snapshot})
}
