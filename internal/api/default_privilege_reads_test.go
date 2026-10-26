package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func defaultPrivilegeTestRule(creator, grantee string) map[string]any {
	return map[string]any{"database": "app", "creator": creator, "schema": "public", "kind": "r", "grantee": grantee, "privilege": "SELECT", "grant_option": false}
}

func TestDefaultPrivilegePageBoundsDirectRulesAndSearch(t *testing.T) {
	rules := make([]map[string]any, 0, 5002)
	for i := range 5000 {
		rules = append(rules, defaultPrivilegeTestRule(fmt.Sprintf("creator_%04d", i), "alice"))
	}
	rules = append(rules, defaultPrivilegeTestRule("public_creator", "PUBLIC"), defaultPrivilegeTestRule("inherited_creator", "readers"))
	topology, err := json.Marshal(map[string]any{"postgres_object_acl_version": 1, "postgres_default_privileges": rules})
	if err != nil {
		t.Fatal(err)
	}
	page, total, available := defaultPrivilegePage(topology, "alice", "", 0, 8)
	if !available || total != 5000 || len(page) != 8 || page[0]["creator"] != "creator_0000" {
		t.Fatalf("first page = %d/%d available=%v", len(page), total, available)
	}
	page, total, available = defaultPrivilegePage(topology, "alice", "", 8, 8)
	if !available || total != 5000 || len(page) != 8 || page[0]["creator"] != "creator_0008" {
		t.Fatalf("next page repeated rules: %+v", page)
	}
	page, total, available = defaultPrivilegePage(topology, "alice", "CREATOR_4999", 0, 8)
	if !available || total != 1 || len(page) != 1 || page[0]["creator"] != "creator_4999" {
		t.Fatalf("server search = %+v / %d available=%v", page, total, available)
	}
	page, total, available = defaultPrivilegePage(topology, "alice", "", 0, 1)
	if !available || total != 5000 || len(page) != 1 {
		t.Fatalf("limit=1 returned %d rules", len(page))
	}
	if page, total, available = defaultPrivilegePage(topology, "nobody", "", 0, 8); !available || total != 0 || len(page) != 0 {
		t.Fatal("observed snapshot without direct rules did not return a known empty result")
	}
}

func TestDefaultPrivilegePageDoesNotFabricateEmptyEvidence(t *testing.T) {
	for _, topology := range []string{
		`{}`, `{"postgres_object_acl_version":1}`, `{"postgres_default_privileges":[]}`,
		`{"postgres_object_acl_version":1,"postgres_default_privileges":null}`,
		`{"postgres_object_acl_version":1,"postgres_default_privileges":{}}`,
		`{"postgres_object_acl_version":1,"postgres_default_privileges":[null]}`,
		`{"postgres_object_acl_version":1,"postgres_default_privileges":[{"grantee":"alice"}]}`,
		`{"postgres_object_acl_version":1,"postgres_default_privileges":[{"database":"app","creator":"owner","schema":"public","kind":"r","grantee":"alice","privilege":"SELECT","grant_option":null}]}`,
	} {
		page, total, available := defaultPrivilegePage(json.RawMessage(topology), "alice", "", 0, 8)
		if available || total != 0 || len(page) != 0 {
			t.Fatalf("malformed/absent evidence reported complete: %s", topology)
		}
	}
	if page, total, available := defaultPrivilegePage(json.RawMessage(`{"postgres_object_acl_version":1,"postgres_default_privileges":[]}`), "alice", "", 0, 8); !available || len(page) != 0 || total != 0 {
		t.Fatal("explicit empty snapshot was unavailable")
	}
}

func TestDefaultPrivilegeCursorPinsPurposeAccountConnectionQueryAndSnapshot(t *testing.T) {
	account, connection := uuid.New(), uuid.New()
	const snapshot = "observed:version:config"
	const query = "SELECT"
	valid := encodeDefaultPrivilegeCursor(account, connection, snapshot, query, 8)
	decoded, err := base64.RawURLEncoding.DecodeString(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		cursor     string
		account    uuid.UUID
		connection uuid.UUID
		query      string
		snapshot   string
		status     int
	}{
		{"valid", valid, account, connection, query, snapshot, http.StatusOK},
		{"foreign account", valid, uuid.New(), connection, query, snapshot, http.StatusBadRequest},
		{"foreign connection", valid, account, uuid.New(), query, snapshot, http.StatusBadRequest},
		{"changed search", valid, account, connection, "UPDATE", snapshot, http.StatusBadRequest},
		{"changed snapshot", valid, account, connection, query, snapshot + "new", http.StatusConflict},
		{"invalid base64", "!!", account, connection, query, snapshot, http.StatusBadRequest},
		{"oversized cursor", strings.Repeat("A", 2049), account, connection, query, snapshot, http.StatusBadRequest},
		{"trailing JSON", base64.RawURLEncoding.EncodeToString(append(decoded, []byte(` {}`)...)), account, connection, query, snapshot, http.StatusBadRequest},
		{"unknown field", base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSuffix(string(decoded), "}") + `,"unexpected":true}`)), account, connection, query, snapshot, http.StatusBadRequest},
		{"foreign purpose", base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(decoded), `"purpose":"defaults"`, `"purpose":"objects"`, 1))), account, connection, query, snapshot, http.StatusBadRequest},
		{"negative offset", base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(decoded), `"offset":8`, `"offset":-1`, 1))), account, connection, query, snapshot, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/?"+url.Values{"q": {tc.query}, "cursor": {tc.cursor}}.Encode(), nil)
			response := httptest.NewRecorder()
			limit, gotQuery, offset, ok := defaultPrivilegePageParameters(response, request, tc.account, tc.connection, tc.snapshot)
			if response.Code != tc.status || ok != (tc.status == http.StatusOK) {
				t.Fatalf("status=%d ok=%v body=%s", response.Code, ok, response.Body.String())
			}
			if ok && (limit != 8 || gotQuery != query || offset != 8) {
				t.Fatalf("page params = %d/%q/%d", limit, gotQuery, offset)
			}
		})
	}
	for _, raw := range []string{"limit=0", "limit=51", "limit=-1", "limit=abc", "q=" + strings.Repeat("a", 257)} {
		response := httptest.NewRecorder()
		if _, _, _, ok := defaultPrivilegePageParameters(response, httptest.NewRequest(http.MethodGet, "/?"+raw, nil), account, connection, snapshot); ok || response.Code != http.StatusBadRequest {
			t.Fatalf("unbounded page accepted: %s", raw)
		}
	}
}
