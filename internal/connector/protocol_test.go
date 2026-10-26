package connector_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

// sampleJob — валидное задание для тестов канонизации/подписи.
func sampleJob() connector.Job {
	return connector.Job{
		ID:              "job-1",
		Kind:            connector.JobApply,
		ConnectionID:    "conn-1",
		Engine:          "postgres",
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        1_700_000_000,
		Deadline:        1_700_000_300,
		IdempotencyKey:  "idem-1",
		Payload:         json.RawMessage(`{"change":"grant"}`),
		Nonce:           "nonce-1",
	}
}

func TestCanonicalBytesDeterministic(t *testing.T) {
	job := sampleJob()

	first, err := connector.CanonicalBytes(job)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	second, err := connector.CanonicalBytes(job)
	if err != nil {
		t.Fatalf("CanonicalBytes (repeat): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("CanonicalBytes not deterministic:\n first=%s\nsecond=%s", first, second)
	}
}

func TestCanonicalBytesIgnoresPayloadFormatting(t *testing.T) {
	compact := sampleJob()
	compact.Payload = json.RawMessage(`{"a":1,"b":2}`)

	spaced := sampleJob()
	spaced.Payload = json.RawMessage("{ \"a\": 1,\n  \"b\": 2 }")

	a, err := connector.CanonicalBytes(compact)
	if err != nil {
		t.Fatalf("CanonicalBytes(compact): %v", err)
	}
	b, err := connector.CanonicalBytes(spaced)
	if err != nil {
		t.Fatalf("CanonicalBytes(spaced): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("whitespace in payload changed canonical bytes:\n a=%s\n b=%s", a, b)
	}
}

func TestCanonicalBytesNilAndEmptyPayloadEqual(t *testing.T) {
	nilPayload := sampleJob()
	nilPayload.Payload = nil

	emptyPayload := sampleJob()
	emptyPayload.Payload = json.RawMessage{}

	a, err := connector.CanonicalBytes(nilPayload)
	if err != nil {
		t.Fatalf("CanonicalBytes(nil): %v", err)
	}
	b, err := connector.CanonicalBytes(emptyPayload)
	if err != nil {
		t.Fatalf("CanonicalBytes(empty): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("nil and empty payload must canonicalize equally:\n a=%s\n b=%s", a, b)
	}
}

func TestCanonicalBytesInvalidPayload(t *testing.T) {
	job := sampleJob()
	job.Payload = json.RawMessage(`{not-json`)

	if _, err := connector.CanonicalBytes(job); err == nil {
		t.Error("CanonicalBytes must fail on invalid JSON payload")
	}
}

// TestCanonicalBytesFieldSensitivity: изменение каждого подписываемого поля
// меняет каноничные байты.
func TestCanonicalBytesFieldSensitivity(t *testing.T) {
	base, err := connector.CanonicalBytes(sampleJob())
	if err != nil {
		t.Fatalf("CanonicalBytes(base): %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*connector.Job)
	}{
		{"ID", func(j *connector.Job) { j.ID = "other" }},
		{"Kind", func(j *connector.Job) { j.Kind = connector.JobPlan }},
		{"ConnectionID", func(j *connector.Job) { j.ConnectionID = "other" }},
		{"Engine", func(j *connector.Job) { j.Engine = "mongodb" }},
		{"ProtocolVersion", func(j *connector.Job) { j.ProtocolVersion = "v2" }},
		{"IssuedAt", func(j *connector.Job) { j.IssuedAt = 42 }},
		{"Deadline", func(j *connector.Job) { j.Deadline = 42 }},
		{"IdempotencyKey", func(j *connector.Job) { j.IdempotencyKey = "other" }},
		{"Payload", func(j *connector.Job) { j.Payload = json.RawMessage(`{"change":"revoke"}`) }},
		{"Nonce", func(j *connector.Job) { j.Nonce = "other" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := sampleJob()
			tc.mutate(&job)
			got, err := connector.CanonicalBytes(job)
			if err != nil {
				t.Fatalf("CanonicalBytes: %v", err)
			}
			if bytes.Equal(base, got) {
				t.Errorf("mutating %s did not change canonical bytes", tc.name)
			}
		})
	}
}

// TestWireTypesCarryNoSecrets — структурная гарантия раздела 24 ("No secrets
// in ... job payload"): типы подписанного задания, результата и payload не
// содержат полей с секретным материалом и не переносят adapter.Credential.
// Секретный материал существует ТОЛЬКО в CredentialsFrame (кадр
// TypeCredentials, ADR-0014) — он сюда сознательно не входит, а его
// недостижимость из Job/JobResult доказывается рекурсией assertSecretFree:
// появись поле с ним в любом из перечисленных типов, тест упал бы на
// секрет-подобных именах (Secret) или adapter.Credential.
func TestWireTypesCarryNoSecrets(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(connector.Job{}),
		reflect.TypeOf(connector.JobResult{}),
		reflect.TypeOf(connector.Envelope{}),
		reflect.TypeOf(connector.Hello{}),
		reflect.TypeOf(connector.ConnectionRef{}),
		reflect.TypeOf(connector.AccountRef{}),
		reflect.TypeOf(connector.DiscoverPayload{}),
		reflect.TypeOf(connector.TLSRef{}),
		reflect.TypeOf(connector.MutationPayload{}),
		reflect.TypeOf(connector.ChangeRef{}),
		reflect.TypeOf(connector.RotatePayload{}),
		reflect.TypeOf(connector.CredentialProofPayload{}),
		reflect.TypeOf(connector.CredentialProofOutcome{}),
		reflect.TypeOf(connector.AdminCredentialPayload{}),
		reflect.TypeOf(connector.SanitizedPlan{}),
		reflect.TypeOf(connector.SanitizedChange{}),
		reflect.TypeOf(connector.SanitizedPlanStep{}),
		reflect.TypeOf(connector.SanitizedResult{}),
		reflect.TypeOf(connector.SanitizedStepResult{}),
		reflect.TypeOf(connector.SanitizedVerification{}),
		reflect.TypeOf(connector.RotateOutcome{}),
		reflect.TypeOf(connector.AdminCredentialOutcome{}),
	}
	for _, typ := range types {
		assertSecretFree(t, typ)
	}
}

var secretNameParts = []string{
	"password", "secret", "token", "privatekey", "passphrase", "adminpassword",
}

// assertSecretFree рекурсивно проверяет, что структура не имеет полей с
// секрет-подобными именами и не переносит adapter.Credential (ни напрямую,
// ни через вложенные структуры пакета connector — включая CredentialsFrame,
// окажись он полем какого-либо wire-типа задания).
func assertSecretFree(t *testing.T, typ reflect.Type) {
	t.Helper()
	credType := reflect.TypeOf(adapter.Credential{})
	ownPkg := reflect.TypeOf(connector.Job{}).PkgPath()

	for i := range typ.NumField() {
		f := typ.Field(i)
		lower := strings.ToLower(f.Name)
		for _, part := range secretNameParts {
			if strings.Contains(lower, part) {
				t.Errorf("%s.%s: field name suggests secret material in a connector wire type",
					typ.Name(), f.Name)
			}
		}

		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft == credType {
			t.Errorf("%s.%s: carries adapter.Credential; secrets must not travel in connector jobs",
				typ.Name(), f.Name)
		}
		if ft.Kind() == reflect.Struct && ft.PkgPath() == ownPkg {
			assertSecretFree(t, ft)
		}
	}
}

// TestHelloDeploymentIsOptionalAndNormalized: поле deployment добавлено к
// Hello как подсказка оператору (ADR-0019). Оно необязательно — агенты
// прошлых версий его не шлют, и такой Hello обязан оставаться валидным, — а
// самообъявление агента не попадает наружу непроверенным: неизвестное
// значение приводится к пустому.
func TestHelloDeploymentIsOptionalAndNormalized(t *testing.T) {
	legacy := []byte(`{"protocol_version":"v1","connector_id":"c-1","capabilities":["access.grant"]}`)
	var hello connector.Hello
	if err := json.Unmarshal(legacy, &hello); err != nil {
		t.Fatalf("decode legacy hello: %v", err)
	}
	if hello.Deployment != "" {
		t.Errorf("legacy hello deployment = %q, want empty", hello.Deployment)
	}

	encoded, err := json.Marshal(connector.Hello{ProtocolVersion: "v1", ConnectorID: "c-1"})
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	if bytes.Contains(encoded, []byte("deployment")) {
		t.Errorf("empty deployment must be omitted, got %s", encoded)
	}

	for _, valid := range []string{
		connector.DeploymentKubernetes, connector.DeploymentVM, connector.DeploymentOther,
	} {
		if got := connector.NormalizeDeployment(valid); got != valid {
			t.Errorf("NormalizeDeployment(%q) = %q, want %q", valid, got, valid)
		}
	}
	for _, invalid := range []string{"", "openshift", "VM", "kubernetes "} {
		if got := connector.NormalizeDeployment(invalid); got != "" {
			t.Errorf("NormalizeDeployment(%q) = %q, want empty", invalid, got)
		}
	}
}
