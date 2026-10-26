package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestConnectionRegistrationStrictCredentialFreeDTO(t *testing.T) {
	valid := connectionRegistrationRequest{RegistrationKey: "ci:cluster-a", RequestID: uuid.New(), DisplayName: "Cluster A", Engine: "postgres", Environment: "test", Endpoints: []string{"10.42.0.1:5432"}, CredentialSourceID: uuid.New(), CredentialSourceVersion: 1}
	if err := valid.validate([]string{"postgres"}); err != nil {
		t.Fatal(err)
	}
	spec, err := valid.spec()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(spec, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"request_id", "registration_key", "password", "username", "vault_path", "credential_source_id"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("comparison spec contains %s", key)
		}
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"vault_admin_path", "mount", "admin_credential", "admin_credential_ref", "network_guard"} {
		payload[field] = "caller-selected-value"
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/connection-registrations", bytes.NewReader(body))
		var decoded connectionRegistrationRequest
		if decodeConnectionOnboardingJSON(w, r, &decoded) {
			t.Fatalf("accepted unsupported field %s", field)
		}
		if strings.Contains(w.Body.String(), "caller-selected-value") {
			t.Fatal("decode error exposed unsupported value")
		}
		delete(payload, field)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)+` {}`))
	var decoded connectionRegistrationRequest
	if decodeConnectionOnboardingJSON(w, r, &decoded) {
		t.Fatal("accepted trailing JSON document")
	}
}

func TestKubernetesDNSSourcePolicyIsDerivedAndBoundToConnectorPlaintext(t *testing.T) {
	target := connectionRegistrationTarget{Engine: "kafka", ExecutionMode: "connector",
		Endpoints: []string{"kafka-cluster.betting-services.svc.cluster.local:9092"}, TLSConfig: []byte(`{"mode":"disabled"}`),
		DiscoveryConfig: []byte(`{"sasl_mechanism":"plain","security_protocol":"sasl_plaintext"}`),
	}
	if err := target.validate([]string{"kafka"}); err != nil {
		t.Fatal(err)
	}
	if target.NetworkGuard != "private-kubernetes-dns.v1" {
		t.Fatal("source target has no derived runtime policy")
	}
	if err := validateCredentialSourceTransport(target); err != nil {
		t.Fatal("guarded headless DNS source rejected")
	}
	for _, mutate := range []func(*connectionRegistrationTarget){
		func(target *connectionRegistrationTarget) { target.ExecutionMode = "direct" },
		func(target *connectionRegistrationTarget) { target.NetworkGuard = "" },
		func(target *connectionRegistrationTarget) { target.NetworkGuard = "unknown-profile" },
		func(target *connectionRegistrationTarget) { target.Endpoints = []string{"db.corporate.example:9092"} },
		func(target *connectionRegistrationTarget) {
			target.Endpoints = []string{"kafka.test.svc.cluster.local.evil:9092"}
		},
		func(target *connectionRegistrationTarget) {
			target.Endpoints = []string{"kafka-cluster.betting-services.svc.cluster.local:9092", "public.example:9092"}
		},
		func(target *connectionRegistrationTarget) { target.TLSConfig = []byte(`{"mode":"verify-ca"}`) },
	} {
		invalid := target
		mutate(&invalid)
		if err := validateCredentialSourceTransport(invalid); err == nil {
			t.Fatal("unbound DNS plaintext approval accepted")
		}
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"network_guard":"private-kubernetes-dns.v1"`)) {
		t.Fatal("immutable source target omitted its policy")
	}
}

func TestCredentialSourceDTOCannotSelectNetworkGuard(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"network_guard":"private-kubernetes-dns.v1"}`))
	var source createConnectionCredentialSourceRequest
	if decodeConnectionOnboardingJSON(w, r, &source) {
		t.Fatal("source caller selected an internal network policy")
	}
}

func TestConnectionRegistrationRequiresVersionedSourceAndScope(t *testing.T) {
	valid := connectionRegistrationRequest{RegistrationKey: "cluster", RequestID: uuid.New(), DisplayName: "Cluster", Engine: "postgres", Environment: "test", Endpoints: []string{"10.42.0.1:5432"}, CredentialSourceID: uuid.New(), CredentialSourceVersion: 1}
	for _, mutate := range []func(*connectionRegistrationRequest){
		func(r *connectionRegistrationRequest) { r.RequestID = uuid.Nil },
		func(r *connectionRegistrationRequest) { r.CredentialSourceVersion = 0 },
		func(r *connectionRegistrationRequest) { r.CredentialSourceID = uuid.Nil },
		func(r *connectionRegistrationRequest) { r.Environment = "" },
		func(r *connectionRegistrationRequest) { r.RegistrationKey = "../other/path" },
		func(r *connectionRegistrationRequest) { r.DiscoveryConfig = []byte(`{"password":"unsupported"}`) },
	} {
		r := valid
		mutate(&r)
		if err := r.validate([]string{"postgres"}); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
}

func TestCredentialSourceTransportCannotDelegatePlaintextPublicOrDNSCredential(t *testing.T) {
	for _, endpoint := range []string{"203.0.113.10:5432", "db.internal.example:5432"} {
		for _, config := range []json.RawMessage{[]byte(`{}`), []byte(`{"mode":"disabled"}`), []byte(`{"mode":"verify-ca"}`), []byte(`{"mode":"verify-full","insecure_skip_verify":true}`)} {
			target := connectionRegistrationTarget{Endpoints: []string{endpoint}, TLSConfig: config}
			if err := validateCredentialSourceTransport(target); err == nil {
				t.Fatalf("insecure transport accepted for %s", endpoint)
			}
		}
		if err := validateCredentialSourceTransport(connectionRegistrationTarget{Endpoints: []string{endpoint}, TLSConfig: []byte(`{"mode":"verify-full"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateCredentialSourceTransport(connectionRegistrationTarget{Endpoints: []string{"10.42.0.1:5432"}, TLSConfig: []byte(`{"mode":"disabled"}`)}); err != nil {
		t.Fatal("explicit private literal approval was rejected")
	}
}
