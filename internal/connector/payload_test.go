package connector_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

// sampleDiscoverPayload — валидный discover payload без секретов: admin
// credential в payload не входит вовсе (ADR-0014, кадр TypeCredentials).
func sampleDiscoverPayload() connector.DiscoverPayload {
	return connector.DiscoverPayload{
		Connection: connector.ConnectionRef{
			ID:        "conn-1",
			Engine:    "postgres",
			Endpoints: []string{"db.internal:5432"},
		},
		TLS:        connector.TLSRef{Mode: "disabled"},
		Attributes: map[string]any{"database": "postgres"},
	}
}

func TestDiscoverPayloadRoundTrip(t *testing.T) {
	payload := sampleDiscoverPayload()
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := connector.ParseDiscoverPayload(raw)
	if err != nil {
		t.Fatalf("ParseDiscoverPayload: %v", err)
	}
	if got.Connection.ID != payload.Connection.ID ||
		got.Connection.Engine != payload.Connection.Engine {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if got.Attributes["database"] != "postgres" {
		t.Errorf("attributes lost: %+v", got.Attributes)
	}
}

func TestDiscoverPayloadDeterministic(t *testing.T) {
	// Deterministic marshaling нужен для воспроизводимой подписи задания.
	payload := sampleDiscoverPayload()
	a, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal (repeat): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("payload marshaling not deterministic:\n a=%s\n b=%s", a, b)
	}
}

func TestParseDiscoverPayloadEmpty(t *testing.T) {
	if _, err := connector.ParseDiscoverPayload(nil); err == nil {
		t.Error("ParseDiscoverPayload(nil) must fail")
	}
	if _, err := connector.ParseDiscoverPayload(json.RawMessage(`{bad`)); err == nil {
		t.Error("ParseDiscoverPayload(invalid) must fail")
	}
}

// TestDiscoverPayloadJSONHasNoSecretKeys — payload не несёт ни
// секрет-подобных ключей, ни ссылок на credentials вовсе: доставку выполняет
// кадр TypeCredentials (ADR-0014), дереференсить connector'у нечего.
func TestDiscoverPayloadJSONHasNoSecretKeys(t *testing.T) {
	raw, err := sampleDiscoverPayload().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range []string{"password", "private_key", "passphrase", "client_key", "secret", "credential", "vault"} {
		if strings.Contains(lower, marker) {
			t.Errorf("discover payload JSON contains secret-related marker %q: %s", marker, raw)
		}
	}
}

// --- Этап 3: payload мутирующих заданий ---

// sampleMutationPayload — валидный mutation payload без секретов: начальный
// credential учётной записи доставляет кадр TypeCredentials, в payload его
// нет вовсе.
func sampleMutationPayload() connector.MutationPayload {
	return connector.MutationPayload{
		Connection: sampleDiscoverPayload().Connection,
		TLS:        connector.TLSRef{Mode: "disabled"},
		Attributes: map[string]any{"database": "postgres"},
		Change: connector.ChangeRef{
			Kind: "account.create",
			Account: connector.AccountRef{
				Kind:           "login",
				EngineIdentity: "svc-1",
			},
		},
	}
}

// sampleRotatePayload — валидный rotate payload: несекретная ссылка на
// учётную запись; новую версию секрета доставляет кадр TypeCredentials.
func sampleRotatePayload() connector.RotatePayload {
	return connector.RotatePayload{
		Connection: sampleDiscoverPayload().Connection,
		TLS:        connector.TLSRef{Mode: "disabled"},
		Account: connector.AccountRef{
			Kind:           "login",
			EngineIdentity: "svc-1",
		},
	}
}

func TestMutationPayloadRoundTrip(t *testing.T) {
	payload := sampleMutationPayload()
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := connector.ParseMutationPayload(raw)
	if err != nil {
		t.Fatalf("ParseMutationPayload: %v", err)
	}
	if got.Change.Kind != payload.Change.Kind ||
		got.Change.Account.EngineIdentity != payload.Change.Account.EngineIdentity ||
		got.Connection.ID != payload.Connection.ID {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

func TestMutationPayloadDeterministic(t *testing.T) {
	payload := sampleMutationPayload()
	a, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal (repeat): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("payload marshaling not deterministic:\n a=%s\n b=%s", a, b)
	}
}

func TestParseMutationPayloadInvalid(t *testing.T) {
	if _, err := connector.ParseMutationPayload(nil); err == nil {
		t.Error("ParseMutationPayload(nil) must fail")
	}
	if _, err := connector.ParseMutationPayload(json.RawMessage(`{bad`)); err == nil {
		t.Error("ParseMutationPayload(invalid) must fail")
	}
	// Пустой ChangeRef.Kind — мутация без описания изменения.
	if _, err := connector.ParseMutationPayload(json.RawMessage(`{"connection":{"id":"c"}}`)); err == nil {
		t.Error("ParseMutationPayload without change kind must fail")
	}
	// Trust boundary использует закрытый allowlist: неизвестный kind нельзя
	// протащить к adapter через вручную собранный wire payload.
	if _, err := connector.ParseMutationPayload(json.RawMessage(
		`{"connection":{"id":"c"},"change":{"kind":"account.superuser"}}`)); err == nil {
		t.Error("ParseMutationPayload with unknown change kind must fail")
	}
	if _, err := connector.ParseMutationPayload(json.RawMessage(
		`{"connection":{"id":"c"},"change":{"kind":"account.restore"}}`)); err != nil {
		t.Errorf("ParseMutationPayload account.restore: %v", err)
	}
}

func TestRoleCreateMutationPayloadClosedContract(t *testing.T) {
	payload := sampleMutationPayload()
	payload.Change = connector.ChangeRef{
		Kind:    string(adapter.ChangeRoleCreate),
		Account: connector.AccountRef{Kind: "group", EngineIdentity: "r_existing_database"},
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("marshal role.create: %v", err)
	}
	parsed, err := connector.ParseMutationPayload(raw)
	if err != nil {
		t.Fatalf("parse role.create: %v", err)
	}
	if parsed.Change.Account != payload.Change.Account || parsed.Change.Kind != payload.Change.Kind {
		t.Fatalf("role.create round trip changed its descriptor: %+v", parsed.Change)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*connector.ChangeRef)
	}{
		{"login identity", func(c *connector.ChangeRef) { c.Account.Kind = "login" }},
		{"missing identity", func(c *connector.ChangeRef) { c.Account.EngineIdentity = "" }},
		{"auth scope", func(c *connector.ChangeRef) { c.Account.AuthenticationScope = "admin" }},
		{"permission", func(c *connector.ChangeRef) { c.Permission = "role:admin" }},
		{"scope", func(c *connector.ChangeRef) { c.Scope = "db:other" }},
		{"memberships", func(c *connector.ChangeRef) { c.AccountPermissions = []string{"role:admin"} }},
		{"attributes", func(c *connector.ChangeRef) { c.Attributes = map[string]any{"superuser": true} }},
		{"policy spec", func(c *connector.ChangeRef) { c.RolePolicySpec = &adapter.RolePolicySpec{} }},
		{"target identity", func(c *connector.ChangeRef) { c.ExpectedTargetIdentity = "postgres:other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := payload
			tc.mutate(&invalid.Change)
			raw, err := invalid.Marshal()
			if err != nil {
				t.Fatalf("marshal invalid role.create: %v", err)
			}
			if _, err := connector.ParseMutationPayload(raw); err == nil {
				t.Fatal("role.create accepted fields outside the bare group-role contract")
			}
		})
	}
}

func TestRolePolicyMutationPayloadClosedContract(t *testing.T) {
	withoutSpec := json.RawMessage(`{"connection":{"id":"c"},"change":{"kind":"role.policy.apply","account_permissions":null}}`)
	if _, err := connector.ParseMutationPayload(withoutSpec); err == nil {
		t.Fatal("role.policy.apply without role_policy_spec must fail before adapter execution")
	}
	implicitBroadMongo := json.RawMessage(`{
		"connection":{"id":"c","engine":"mongodb"},
		"change":{"kind":"role.policy.apply","permission":"role:admin.broad",
		"expected_target_identity":"mongodb:replica-set:65f15f1276d3f744be6c0711",
		"role_policy_spec":{"engine":"mongodb","key":"broad","name":"Broad",
		"description":"Broad","role_name":"broad","database":"admin",
		"schemas":[],"owner_roles":[],"creator_roles":[],"profile":"",
		"privileges":[{"resource":{"db":null,"collection":null},"actions":["find"]}]}}}`)
	if _, err := connector.ParseMutationPayload(implicitBroadMongo); err == nil {
		t.Fatal("role policy resource with null namespace fields must fail at connector boundary")
	}
	spec := adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read",
		Description: "Read app", RoleName: "r_app", Database: "app",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
	missingTarget := connector.MutationPayload{
		Connection: connector.ConnectionRef{ID: "c", Engine: "postgres"},
		Change: connector.ChangeRef{
			Kind: string(adapter.ChangeRolePolicyApply), Permission: "role:r_app",
			RolePolicySpec: &spec,
		},
	}
	missingTargetRaw, err := missingTarget.Marshal()
	if err != nil {
		t.Fatalf("marshal missing target: %v", err)
	}
	if _, err := connector.ParseMutationPayload(missingTargetRaw); err == nil {
		t.Fatal("role.policy.apply without expected_target_identity must fail before adapter execution")
	}
	payload := connector.MutationPayload{
		Connection: connector.ConnectionRef{ID: "c", Engine: "postgres"},
		Change: connector.ChangeRef{
			Kind: string(adapter.ChangeRolePolicyVerify), Permission: "role:r_app",
			RolePolicySpec:         &spec,
			ExpectedTargetIdentity: "postgres:system:7429012345678901234",
		},
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := connector.ParseMutationPayload(raw)
	if err != nil {
		t.Fatalf("parse role policy payload: %v", err)
	}
	if parsed.Change.RolePolicySpec == nil || parsed.Change.RolePolicySpec.Profile != "read" {
		t.Fatalf("parsed spec = %+v", parsed.Change.RolePolicySpec)
	}
	payload.Change.Kind = string(adapter.ChangeRolePolicyCreate)
	raw, err = payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = connector.ParseMutationPayload(raw)
	if err != nil || parsed.Change.Kind != string(adapter.ChangeRolePolicyCreate) {
		t.Fatalf("create-only kind must survive transport without Apply fallback: %+v, %v", parsed.Change, err)
	}

	mongoSpec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "cluster-observer", Name: "Cluster observer",
		Description: "Typed MongoDB policy", RoleName: "clusterObserver", Database: "admin",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		MongoPrivileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"serverStatus"},
		}},
	}
	mongoPayload := connector.MutationPayload{
		Connection: connector.ConnectionRef{ID: "mongo", Engine: "mongodb"},
		Change: connector.ChangeRef{
			Kind: string(adapter.ChangeRolePolicyApply), Permission: "role:admin.clusterObserver",
			RolePolicySpec:         &mongoSpec,
			ExpectedTargetIdentity: "mongodb:replica-set:65f15f1276d3f744be6c0711",
		},
	}
	mongoRaw, err := mongoPayload.Marshal()
	if err != nil {
		t.Fatalf("marshal MongoDB policy: %v", err)
	}
	mongoParsed, err := connector.ParseMutationPayload(mongoRaw)
	if err != nil {
		t.Fatalf("parse MongoDB policy: %v", err)
	}
	gotMongo := mongoParsed.Change.RolePolicySpec
	if gotMongo == nil || gotMongo.Engine != "mongodb" || len(gotMongo.MongoInheritedRoles) != 1 ||
		len(gotMongo.MongoPrivileges) != 1 || !gotMongo.MongoPrivileges[0].Resource.Cluster ||
		len(gotMongo.MongoPrivileges[0].Actions) != 1 ||
		gotMongo.MongoPrivileges[0].Actions[0] != "serverStatus" {
		t.Fatalf("parsed MongoDB spec = %+v", gotMongo)
	}
	mongoPayload.Change.Kind = string(adapter.ChangeRolePolicyCreate)
	mongoRaw, err = mongoPayload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.ParseMutationPayload(mongoRaw); err == nil {
		t.Fatal("PostgreSQL create-only must not accept MongoDB policies")
	}
}

func TestAdminCredentialPayloadRoundTripAndClosedMode(t *testing.T) {
	for _, mode := range []connector.AdminCredentialMode{
		connector.AdminCredentialModeSwitch,
		connector.AdminCredentialModeRotate,
	} {
		t.Run(string(mode), func(t *testing.T) {
			payload := connector.AdminCredentialPayload{
				Connection: connector.ConnectionRef{
					ID: "conn-admin", Engine: "postgres",
					Endpoints: []string{"db.internal:5432"},
				},
				TLS:               connector.TLSRef{Mode: "verify-full", CACertPEM: []byte("public-ca")},
				Attributes:        map[string]any{"database": "postgres"},
				CandidateUsername: "grantor_admin", Epoch: 7, Mode: mode,
			}
			if mode == connector.AdminCredentialModeRotate {
				payload.ExpectedCanonicalIdentity = "grantor_admin"
				payload.ExpectedAuthorityFingerprint = "authority-v1"
				payload.ExpectedTargetIdentity = "postgres:system:1"
			}
			raw, err := payload.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := connector.ParseAdminCredentialPayload(raw)
			if err != nil {
				t.Fatalf("ParseAdminCredentialPayload: %v", err)
			}
			kind, err := got.JobKind()
			if err != nil {
				t.Fatalf("JobKind: %v", err)
			}
			wantKind := connector.JobAdminCredentialSwitch
			if mode == connector.AdminCredentialModeRotate {
				wantKind = connector.JobAdminCredentialRotate
			}
			if got.CandidateUsername != payload.CandidateUsername || got.Epoch != 7 || kind != wantKind {
				t.Fatalf("round-trip = %+v / %q, want candidate/epoch/kind preserved", got, kind)
			}
			for _, marker := range []string{"password", "private_key", "passphrase", "client_key", "secret", "vault"} {
				if strings.Contains(strings.ToLower(string(raw)), marker) {
					t.Fatalf("admin credential payload contains secret marker %q: %s", marker, raw)
				}
			}
		})
	}

	valid := connector.AdminCredentialPayload{
		Connection:        connector.ConnectionRef{ID: "conn", Engine: "postgres"},
		CandidateUsername: "admin", Epoch: 1, Mode: connector.AdminCredentialModeSwitch,
	}
	rotateWithoutFence := valid
	rotateWithoutFence.Mode = connector.AdminCredentialModeRotate
	if _, err := rotateWithoutFence.Marshal(); err == nil {
		t.Fatal("rotate payload without pre-mutation proof fence was accepted")
	}
	switchWithFence := valid
	switchWithFence.ExpectedCanonicalIdentity = "admin"
	switchWithFence.ExpectedAuthorityFingerprint = "authority"
	switchWithFence.ExpectedTargetIdentity = "target"
	if _, err := switchWithFence.Marshal(); err == nil {
		t.Fatal("switch payload with rotate-only proof fence was accepted")
	}
	for name, mutate := range map[string]func(*connector.AdminCredentialPayload){
		"connection": func(p *connector.AdminCredentialPayload) { p.Connection.ID = "" },
		"engine":     func(p *connector.AdminCredentialPayload) { p.Connection.Engine = "" },
		"candidate":  func(p *connector.AdminCredentialPayload) { p.CandidateUsername = "" },
		"epoch":      func(p *connector.AdminCredentialPayload) { p.Epoch = 0 },
		"mode":       func(p *connector.AdminCredentialPayload) { p.Mode = "generic_rotate" },
	} {
		t.Run("reject "+name, func(t *testing.T) {
			payload := valid
			mutate(&payload)
			if _, err := payload.Marshal(); err == nil {
				t.Fatal("Marshal accepted incomplete or unknown-mode admin credential payload")
			}
		})
	}
	if _, err := connector.ParseAdminCredentialPayload(nil); err == nil {
		t.Fatal("ParseAdminCredentialPayload(nil) must fail")
	}
}

func TestRotatePayloadRoundTrip(t *testing.T) {
	payload := sampleRotatePayload()
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := connector.ParseRotatePayload(raw)
	if err != nil {
		t.Fatalf("ParseRotatePayload: %v", err)
	}
	if got.Account.EngineIdentity != "svc-1" || got.Account.Kind != "login" {
		t.Errorf("round-trip mismatch: %+v", got.Account)
	}
}

func TestParseRotatePayloadRequiresAccountIdentity(t *testing.T) {
	if _, err := connector.ParseRotatePayload(nil); err == nil {
		t.Error("ParseRotatePayload(nil) must fail")
	}
	// Без identity учётной записи ротация неадресуема.
	raw, err := connector.RotatePayload{
		Connection: sampleDiscoverPayload().Connection,
		Account:    connector.AccountRef{Kind: "login"},
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := connector.ParseRotatePayload(raw); err == nil {
		t.Error("ParseRotatePayload without account identity must fail")
	}
}

// TestMutationPayloadsJSONHaveNoSecretKeys — payload мутаций и ротации не
// несут ни секрет-подобных ключей, ни ссылок на credentials: доставку
// выполняет кадр TypeCredentials (ADR-0014).
func TestMutationPayloadsJSONHaveNoSecretKeys(t *testing.T) {
	mut, err := sampleMutationPayload().Marshal()
	if err != nil {
		t.Fatalf("Marshal mutation: %v", err)
	}
	rot, err := sampleRotatePayload().Marshal()
	if err != nil {
		t.Fatalf("Marshal rotate: %v", err)
	}
	for name, raw := range map[string][]byte{"mutation": mut, "rotate": rot} {
		lower := strings.ToLower(string(raw))
		for _, marker := range []string{"password", "private_key", "passphrase", "client_key", "secret", "credential", "vault"} {
			if strings.Contains(lower, marker) {
				t.Errorf("%s payload JSON contains secret-related marker %q: %s", name, marker, raw)
			}
		}
	}
}
