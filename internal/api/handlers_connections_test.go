package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeleteConnectionGuard(t *testing.T) {
	cases := []struct {
		name            string
		managedAccounts int
		force           bool
		wantAllowed     bool
	}{
		{"no managed accounts", 0, false, true},
		{"no managed accounts with force", 0, true, true},
		{"managed accounts without force refuse", 3, false, false},
		{"managed accounts with force allow", 3, true, true},
		{"single managed account without force refuse", 1, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, allowed := deleteConnectionGuard(tc.managedAccounts, tc.force)
			if allowed != tc.wantAllowed {
				t.Fatalf("deleteConnectionGuard(%d, %v) allowed = %v, want %v",
					tc.managedAccounts, tc.force, allowed, tc.wantAllowed)
			}
			switch {
			case allowed && msg != "":
				t.Errorf("allowed guard returned non-empty message %q", msg)
			case !allowed && msg == "":
				t.Error("refused guard returned empty message")
			case !allowed && !strings.Contains(msg, "orphaned"):
				// Сообщение обязано объяснять последствие (орфанинг на target).
				t.Errorf("refuse message does not mention orphaning: %q", msg)
			}
		})
	}
}

func TestPatchConnectionNestedConfigValidation(t *testing.T) {
	validTLS := json.RawMessage(`{"mode":"verify-full"}`)
	tlsCfg, err := validateTLSConfig(validTLS)
	if err != nil {
		t.Fatalf("validateTLSConfig(valid): %v", err)
	}
	if tlsCfg.Mode != "verify-full" {
		t.Fatalf("tls mode = %q, want verify-full", tlsCfg.Mode)
	}

	for _, raw := range []json.RawMessage{
		json.RawMessage(`null`),
		json.RawMessage(`[]`),
		json.RawMessage(`{"mode":"bogus"}`),
		json.RawMessage(`{"mode":"disabled","private_key":"secret"}`),
		json.RawMessage(`{"mode":"verify-full","ca_cert_pem":"not pem"}`),
	} {
		if _, err := validateTLSConfig(raw); err == nil {
			t.Errorf("validateTLSConfig(%s): expected error", raw)
		}
	}

	if err := validateDiscoveryConfig(
		json.RawMessage(`{"database":"app"}`), "postgres", editableTLSConfig{},
	); err != nil {
		t.Fatalf("validateDiscoveryConfig(postgres): %v", err)
	}
	if err := validateDiscoveryConfig(
		json.RawMessage(`{"auth_source":"admin","replica_set":"rs0"}`), "mongodb", editableTLSConfig{},
	); err != nil {
		t.Fatalf("validateDiscoveryConfig(mongodb): %v", err)
	}
	if err := validateDiscoveryConfig(
		json.RawMessage(`{"mongodb_role_policy_templates":[{
			"key":"app-worker","name":"Application worker","description":"App data",
			"role_name":"app_worker","role_database":"app",
			"inherited_roles":[{"role":"read","db":"app"}],
			"privileges":[{"resource":{"db":"app","collection":"events"},"actions":["find","update"]}]
		}]}`), "mongodb", editableTLSConfig{},
	); err != nil {
		t.Fatalf("validateDiscoveryConfig(mongodb templates): %v", err)
	}
	if err := validateDiscoveryConfig(
		json.RawMessage(`{"rabbitmq_permission_templates":[{"key":"etl","name":"ETL","description":"ETL queues","vhost":"sl","configure":"^status$","write":"^updates$","read":"^(status|updates)$","dangerous":false}]}`),
		"rabbitmq", editableTLSConfig{},
	); err != nil {
		t.Fatalf("validateDiscoveryConfig(rabbitmq templates): %v", err)
	}
	for _, tc := range []struct {
		name   string
		raw    json.RawMessage
		engine string
		tls    editableTLSConfig
	}{
		{"unknown field", json.RawMessage(`{"password":"secret"}`), "postgres", editableTLSConfig{}},
		{"sasl on postgres", json.RawMessage(`{"sasl_mechanism":"plain"}`), "postgres", editableTLSConfig{}},
		{"auth_source on postgres", json.RawMessage(`{"auth_source":"admin"}`), "postgres", editableTLSConfig{}},
		{"replica_set on postgres", json.RawMessage(`{"replica_set":"rs0"}`), "postgres", editableTLSConfig{}},
		{"rabbit templates on postgres", json.RawMessage(`{"rabbitmq_permission_templates":[{"key":"x","name":"X","description":"X","vhost":"/","configure":"^$","write":"^$","read":"^$","dangerous":false}]}`), "postgres", editableTLSConfig{}},
		{"empty rabbit templates on postgres", json.RawMessage(`{"rabbitmq_permission_templates":[]}`), "postgres", editableTLSConfig{}},
		{"rabbit template unknown field", json.RawMessage(`{"rabbitmq_permission_templates":[{"key":"x","name":"X","description":"X","vhost":"/","configure":"^$","write":"^$","read":"^$","dangerous":false,"extra":true}]}`), "rabbitmq", editableTLSConfig{}},
		{"rabbit template invalid regex", json.RawMessage(`{"rabbitmq_permission_templates":[{"key":"x","name":"X","description":"X","vhost":"/","configure":"(","write":"^$","read":"^$","dangerous":false}]}`), "rabbitmq", editableTLSConfig{}},
		{"rabbit template duplicates legacy", json.RawMessage(`{"rabbitmq_permission_templates":[{"key":"x","name":"X","description":"X","vhost":"/","configure":".*","write":".*","read":".*","dangerous":false}]}`), "rabbitmq", editableTLSConfig{}},
		{"mongo templates on postgres", json.RawMessage(`{"mongodb_role_policy_templates":[]}`), "postgres", editableTLSConfig{}},
		{"mongo template raw bson", json.RawMessage(`{"mongodb_role_policy_templates":[{"key":"x","name":"X","description":"X","role_name":"x","role_database":"app","inherited_roles":[],"privileges":[],"raw_bson":{}}]}`), "mongodb", editableTLSConfig{}},
		{"mongo template unknown action", json.RawMessage(`{"mongodb_role_policy_templates":[{"key":"x","name":"X","description":"X","role_name":"x","role_database":"app","inherited_roles":[],"privileges":[{"resource":{"db":"app","collection":""},"actions":["runCommand"]}]}]}`), "mongodb", editableTLSConfig{}},
		{"mongo template any resource", json.RawMessage(`{"mongodb_role_policy_templates":[{"key":"x","name":"X","description":"X","role_name":"x","role_database":"admin","inherited_roles":[],"privileges":[{"resource":{"any_resource":true},"actions":["find"]}]}]}`), "mongodb", editableTLSConfig{}},
		{"bad sasl", json.RawMessage(`{"sasl_mechanism":"oauth"}`), "kafka", editableTLSConfig{}},
		{"ssl without tls", json.RawMessage(`{"security_protocol":"sasl_ssl"}`), "kafka", editableTLSConfig{Mode: "disabled"}},
		{"plaintext with tls", json.RawMessage(`{"security_protocol":"plaintext"}`), "kafka", editableTLSConfig{Mode: "verify-full"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDiscoveryConfig(tc.raw, tc.engine, tc.tls); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMongoDBRolePolicySpecsUseRoleDatabaseAndCanonicalPrivileges(t *testing.T) {
	raw := json.RawMessage(`{"mongodb_role_policy_templates":[{
		"key":"app-worker","name":"Application worker","description":"App data",
		"role_name":"app_worker","role_database":"app",
		"inherited_roles":[{"role":"read","db":"app"},{"role":"read","db":"app"}],
		"privileges":[
			{"resource":{"db":"app","collection":"events"},"actions":["update","find"]},
			{"resource":{"db":"app","collection":"events"},"actions":["find","insert"]}
		]
	}]}`)
	specs, err := mongodbRolePolicySpecs(raw)
	if err != nil {
		t.Fatalf("mongodbRolePolicySpecs: %v", err)
	}
	if len(specs) != 1 || specs[0].Engine != "mongodb" || specs[0].Database != "app" ||
		len(specs[0].MongoInheritedRoles) != 1 || len(specs[0].MongoPrivileges) != 1 {
		t.Fatalf("specs = %+v", specs)
	}
	wantActions := []string{"find", "insert", "update"}
	if got := specs[0].MongoPrivileges[0].Actions; strings.Join(got, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("actions = %v, want %v", got, wantActions)
	}
}
