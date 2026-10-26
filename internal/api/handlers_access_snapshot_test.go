package api

// Юнит-тесты снапшота доступов: разбор sections, маршрутизация
// managed-only, байт-совместимость manifest-пути с прежним выводом,
// сборка документа снапшота, паритет yaml/json-тегов и отказ apply
// принимать снапшот как манифест.

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/accessmanifest"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

func TestParseExportSections(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    map[string]bool
		wantErr bool
	}{
		{name: "absent", raw: "", want: nil},
		{name: "managed only", raw: "managed", want: map[string]bool{"managed": true}},
		{name: "all with spaces", raw: "managed, unmanaged ,roles,accounts",
			want: map[string]bool{"managed": true, "unmanaged": true, "roles": true, "accounts": true}},
		{name: "duplicates collapse", raw: "roles,roles", want: map[string]bool{"roles": true}},
		{name: "unknown value", raw: "managed,bogus", wantErr: true},
		{name: "empty item", raw: "managed,", wantErr: true},
		{name: "only comma", raw: ",", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExportSections(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseExportSections(%q): expected error, got %v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExportSections(%q): unexpected error: %v", tc.raw, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseExportSections(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestManifestOnlySections закрепляет маршрутизацию export: отсутствие
// sections и ровно managed идут прежним manifest-путём, всё остальное — в
// ветку снапшота.
func TestManifestOnlySections(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "", want: true},
		{raw: "managed", want: true},
		{raw: "managed,managed", want: true},
		{raw: "unmanaged", want: false},
		{raw: "managed,unmanaged", want: false},
		{raw: "roles,accounts", want: false},
	}
	for _, tc := range cases {
		sections, err := parseExportSections(tc.raw)
		if err != nil {
			t.Fatalf("parseExportSections(%q): %v", tc.raw, err)
		}
		if got := manifestOnlySections(sections); got != tc.want {
			t.Errorf("manifestOnlySections(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// exportFixtureManifest — фиксированный манифест для проверки
// байт-совместимости manifest-пути export.
func exportFixtureManifest() accessmanifest.Manifest {
	return accessmanifest.Manifest{
		Version: accessmanifest.Version,
		Entries: []accessmanifest.Entry{
			{Principal: "svc", Connection: "pg-main", Role: "role:ro", State: "present"},
		},
	}
}

// TestExportManagedOnlyByteCompat — доказательство байт-совместимости
// managed-only export: манифест сериализуется теми же helpers
// (respondJSON/respondYAML) и теми же структурами, что и до появления
// sections, поэтому вывод обязан посимвольно совпадать с зафиксированным
// здесь выводом прежней реализации (goldens сняты с неё).
func TestExportManagedOnlyByteCompat(t *testing.T) {
	const goldenJSON = `{"version":"v1","entries":[{"principal":"svc","connection":"pg-main","role":"role:ro","state":"present"}]}` + "\n"
	const goldenYAML = `version: v1
entries:
  - principal: svc
    connection: pg-main
    role: role:ro
    state: present
`

	rec := httptest.NewRecorder()
	respondJSON(rec, http.StatusOK, exportFixtureManifest())
	if got := rec.Body.String(); got != goldenJSON {
		t.Errorf("managed-only JSON output changed:\ngot  %q\nwant %q", got, goldenJSON)
	}

	rec = httptest.NewRecorder()
	respondYAML(rec, http.StatusOK, exportFixtureManifest())
	if got := rec.Body.String(); got != goldenYAML {
		t.Errorf("managed-only YAML output changed:\ngot  %q\nwant %q", got, goldenYAML)
	}
}

// snapshotFixture — подключение и данные всех секций для юнит-тестов
// сборки снапшота (без БД).
func snapshotFixture() (connections.Connection, snapshotSourceData) {
	conn := connections.Connection{
		ID:          uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		DisplayName: "pg-main",
		Engine:      "postgres",
		Environment: "test",
	}
	principalID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	managedAcct := inventory.Account{
		ID:             uuid.MustParse("33333333-3333-3333-3333-333333333331"),
		PrincipalID:    &principalID,
		Kind:           "login",
		EngineIdentity: "svc",
		VaultPath:      "principals/22222222/environments/test/credential",
		Status:         inventory.AccountActive,
		Ownership:      inventory.OwnershipManaged,
	}
	unmanagedAcct := inventory.Account{
		ID:             uuid.MustParse("33333333-3333-3333-3333-333333333332"),
		Kind:           "group",
		EngineIdentity: "readers",
		Status:         inventory.AccountActive,
		Ownership:      inventory.OwnershipUnmanaged,
	}
	scopeID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	roPerm := inventory.Permission{
		ID:         uuid.MustParse("55555555-5555-5555-5555-555555555551"),
		ExternalID: "role:app-readonly",
		Name:       "app-readonly",
		Assignable: true,
	}
	scopedPerm := inventory.Permission{
		ID:              uuid.MustParse("55555555-5555-5555-5555-555555555552"),
		ExternalID:      "role:db-owner",
		Name:            "db-owner",
		ScopeResourceID: &scopeID,
		Assignable:      true,
		Dangerous:       true,
	}
	desired := inventory.BindingPresent
	data := snapshotSourceData{
		accounts:    []inventory.Account{unmanagedAcct, managedAcct},
		permissions: []inventory.Permission{roPerm, scopedPerm},
		resources: []inventory.Resource{
			{ID: scopeID, Kind: "database", Name: "app"},
		},
		bindings: []inventory.Binding{
			// Managed binding: в секцию unmanaged не попадает.
			{AccountID: managedAcct.ID, PermissionDefinitionID: roPerm.ID,
				DesiredState: &desired, ObservedState: inventory.BindingPresent},
			// Unmanaged со scope и unmanaged connection-wide (порядок в
			// снапшоте — по account/role/scope, не по входному срезу).
			{AccountID: unmanagedAcct.ID, PermissionDefinitionID: scopedPerm.ID,
				ScopeResourceID: &scopeID, ObservedState: inventory.BindingPresent},
			{AccountID: unmanagedAcct.ID, PermissionDefinitionID: roPerm.ID,
				ObservedState: inventory.BindingPresent},
		},
		principals: map[uuid.UUID]principals.Principal{
			principalID: {ID: principalID, DisplayName: "Service", ExternalSubject: "ext-svc"},
		},
	}
	return conn, data
}

func TestBuildAccessSnapshotAllSections(t *testing.T) {
	conn, data := snapshotFixture()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	sections := map[string]bool{"managed": true, "unmanaged": true, "roles": true, "accounts": true}

	snap := buildAccessSnapshot(conn, now, sections, data)

	if snap.Kind != "access_snapshot" {
		t.Errorf("kind = %q, want access_snapshot", snap.Kind)
	}
	if snap.Connection.ID != conn.ID || snap.Connection.DisplayName != "pg-main" ||
		snap.Connection.Engine != "postgres" || snap.Connection.Environment != "test" {
		t.Errorf("connection block = %+v", snap.Connection)
	}
	if !snap.GeneratedAt.Equal(now) {
		t.Errorf("generated_at = %v, want %v", snap.GeneratedAt, now)
	}

	// Managed-секция теперь строится из инвентаря: аккаунт заполнен всегда,
	// принципал — когда привязан (см. snapshotManagedEntry).
	wantManaged := []snapshotManagedEntry{{
		Principal: "ext-svc", Account: "svc",
		Role: "role:app-readonly", State: "present",
	}}
	if snap.Managed == nil || !reflect.DeepEqual(*snap.Managed, wantManaged) {
		t.Errorf("managed = %+v, want %+v", snap.Managed, wantManaged)
	}

	wantUnmanaged := []snapshotUnmanagedBinding{
		{Account: "readers", Role: "app-readonly", ObservedState: "present"},
		{Account: "readers", Role: "db-owner", Scope: "app", ObservedState: "present"},
	}
	if snap.Unmanaged == nil || !reflect.DeepEqual(*snap.Unmanaged, wantUnmanaged) {
		t.Errorf("unmanaged = %+v, want %+v", snap.Unmanaged, wantUnmanaged)
	}

	wantRoles := []snapshotRole{
		{Name: "app-readonly", ExternalID: "role:app-readonly", Assignable: true},
		{Name: "db-owner", ExternalID: "role:db-owner", Assignable: true, Dangerous: true, Scope: "app"},
	}
	if snap.Roles == nil || !reflect.DeepEqual(*snap.Roles, wantRoles) {
		t.Errorf("roles = %+v, want %+v", snap.Roles, wantRoles)
	}

	wantAccounts := []snapshotAccount{
		{EngineIdentity: "readers", Kind: "group", Ownership: "unmanaged", Status: "active"},
		{EngineIdentity: "svc", Kind: "login", Ownership: "managed", Status: "active", Principal: "ext-svc"},
	}
	if snap.Accounts == nil || !reflect.DeepEqual(*snap.Accounts, wantAccounts) {
		t.Errorf("accounts = %+v, want %+v", snap.Accounts, wantAccounts)
	}
}

// TestBuildAccessSnapshotOnlyRequestedSections проверяет, что в документе
// присутствуют только запрошенные секции, а запрошенная пустая секция —
// именно пустой срез (сериализуется как []), не nil.
func TestBuildAccessSnapshotOnlyRequestedSections(t *testing.T) {
	conn, _ := snapshotFixture()
	snap := buildAccessSnapshot(conn, time.Now(), map[string]bool{"unmanaged": true}, snapshotSourceData{})

	if snap.Managed != nil || snap.Roles != nil || snap.Accounts != nil {
		t.Errorf("unrequested sections present: managed=%v roles=%v accounts=%v",
			snap.Managed, snap.Roles, snap.Accounts)
	}
	if snap.Unmanaged == nil {
		t.Fatal("requested unmanaged section is nil")
	}
	if len(*snap.Unmanaged) != 0 {
		t.Errorf("unmanaged = %+v, want empty", *snap.Unmanaged)
	}
}

// TestAccessSnapshotTagParity — у каждого поля типов снапшота yaml-тег в
// точности повторяет json-тег (имя и опции): JSON и YAML — один документ в
// двух сериализациях (см. одноимённый тест Manifest/Entry).
func TestAccessSnapshotTagParity(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(accessSnapshot{}),
		reflect.TypeOf(snapshotConnection{}),
		reflect.TypeOf(snapshotManagedEntry{}),
		reflect.TypeOf(snapshotUnmanagedBinding{}),
		reflect.TypeOf(snapshotRole{}),
		reflect.TypeOf(snapshotAccount{}),
	} {
		for i := range typ.NumField() {
			field := typ.Field(i)
			jsonTag, jsonOK := field.Tag.Lookup("json")
			yamlTag, yamlOK := field.Tag.Lookup("yaml")
			if !jsonOK || !yamlOK {
				t.Errorf("%s.%s: json tag present=%v, yaml tag present=%v, want both",
					typ.Name(), field.Name, jsonOK, yamlOK)
				continue
			}
			if jsonTag != yamlTag {
				t.Errorf("%s.%s: yaml tag %q differs from json tag %q",
					typ.Name(), field.Name, yamlTag, jsonTag)
			}
		}
	}
}

// TestApplyRejectsSnapshotBody — снапшот не является манифестом и не
// применяется: тело kind=access_snapshot декодируется decodeManifestBody
// (лишние поля JSON/YAML игнорируются), но валидация манифеста отвергает
// его с понятной ошибкой про version — у снапшота нет version/entries.
func TestApplyRejectsSnapshotBody(t *testing.T) {
	const snapshotJSON = `{
  "kind": "access_snapshot",
  "connection": {"id": "11111111-1111-1111-1111-111111111111", "display_name": "pg-main", "engine": "postgres", "environment": "test"},
  "generated_at": "2026-07-19T12:00:00Z",
  "unmanaged": [{"account": "readers", "role": "app-readonly", "observed_state": "present"}]
}`
	const snapshotYAML = `kind: access_snapshot
connection:
  id: 11111111-1111-1111-1111-111111111111
  display_name: pg-main
  engine: postgres
  environment: test
generated_at: 2026-07-19T12:00:00Z
unmanaged:
  - account: readers
    role: app-readonly
    observed_state: present
`
	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "json snapshot", contentType: "application/json", body: snapshotJSON},
		{name: "yaml snapshot", contentType: "application/yaml", body: snapshotYAML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/access/apply", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			rec := httptest.NewRecorder()
			var dst manifestApplyRequest
			if ok := decodeManifestBody(rec, req, &dst); !ok {
				t.Fatalf("decodeManifestBody failed: status %d body %s", rec.Code, rec.Body.String())
			}
			err := dst.Validate()
			if err == nil {
				t.Fatal("Validate() accepted an access snapshot as a manifest")
			}
			if !strings.Contains(err.Error(), "version") {
				t.Errorf("Validate() error = %q, want mention of unsupported version", err)
			}
		})
	}
}
