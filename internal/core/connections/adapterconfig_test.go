package connections

import (
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

// TestAdapterConfigIdentityAttributes проверяет, что несекретные параметры
// составной engine identity доезжают из discovery_config в Attributes
// adapter: без этого mongodb всегда получал бы auth_source "admin", а
// mysql — host "%", независимо от настроек подключения.
func TestAdapterConfigIdentityAttributes(t *testing.T) {
	cfg, err := AdapterConfig(Connection{
		ID:              uuid.New(),
		Engine:          "mongodb",
		DiscoveryConfig: []byte(`{"auth_source":"apps","database":"maint"}`),
	})
	if err != nil {
		t.Fatalf("AdapterConfig: %v", err)
	}
	if got := cfg.Attributes["auth_source"]; got != "apps" {
		t.Errorf("attributes[auth_source] = %v, want apps", got)
	}
	if got := cfg.Attributes["database"]; got != "maint" {
		t.Errorf("attributes[database] = %v, want maint", got)
	}

	cfg, err = AdapterConfig(Connection{
		ID:              uuid.New(),
		Engine:          "mysql",
		DiscoveryConfig: []byte(`{"default_account_host":"10.%"}`),
	})
	if err != nil {
		t.Fatalf("AdapterConfig: %v", err)
	}
	if got := cfg.Attributes["default_account_host"]; got != "10.%" {
		t.Errorf("attributes[default_account_host] = %v, want 10.%%", got)
	}
}

func TestAdapterConfigRabbitMQPermissionTemplates(t *testing.T) {
	cfg, err := AdapterConfig(Connection{
		ID: uuid.New(), Engine: "rabbitmq",
		DiscoveryConfig: []byte(`{"rabbitmq_permission_templates":[{"key":"etl","name":"ETL","description":"ETL queues","vhost":"sl","configure":"^status$","write":"^updates$","read":"^(status|updates)$","dangerous":false}]}`),
	})
	if err != nil {
		t.Fatalf("AdapterConfig: %v", err)
	}
	templates, err := rabbitmqconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(templates) != 1 || templates[0].Key != "etl" || templates[0].Write != "^updates$" {
		t.Fatalf("templates = %+v", templates)
	}
}

func TestAdapterConfigPostgresRolePolicyTemplates(t *testing.T) {
	cfg, err := AdapterConfig(Connection{
		ID: uuid.New(), Engine: "postgres",
		DiscoveryConfig: []byte(`{"postgres_role_policy_templates":[{
			"key":"app-read","name":"Application read","description":"Read app",
			"role_name":"r_app","database":"app","schemas":["public"],
			"owner_roles":["app_owner"],"creator_roles":["app_migrator"],
			"profile":"read"
		}]}`),
	})
	if err != nil {
		t.Fatalf("AdapterConfig: %v", err)
	}
	templates, err := postgresconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(templates) != 1 || templates[0].Key != "app-read" ||
		templates[0].CreatorRoles[0] != "app_migrator" {
		t.Fatalf("templates = %+v", templates)
	}
}

func TestAdapterConfigMongoDBRolePolicyTemplates(t *testing.T) {
	cfg, err := AdapterConfig(Connection{
		ID: uuid.New(), Engine: "mongodb",
		DiscoveryConfig: []byte(`{"mongodb_role_policy_templates":[{
			"key":"app-worker","name":"Application worker","description":"App data",
			"role_name":"app_worker","role_database":"app",
			"inherited_roles":[{"role":"read","db":"app"}],
			"privileges":[{"resource":{"db":"app","collection":"events"},"actions":["find","update"]}]
		}]}`),
	})
	if err != nil {
		t.Fatalf("AdapterConfig: %v", err)
	}
	templates, err := mongodbconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(templates) != 1 || templates[0].RoleDatabase != "app" ||
		templates[0].Privileges[0].Actions[0] != "find" {
		t.Fatalf("templates = %+v", templates)
	}
}

// TestAdapterConfigEmptyAttributesOmitted фиксирует прежнее поведение:
// пустые значения в Attributes не попадают.
func TestAdapterConfigEmptyAttributesOmitted(t *testing.T) {
	for _, discoveryConfig := range [][]byte{nil, []byte(`{"database_create":{}}`)} {
		cfg, err := AdapterConfig(Connection{ID: uuid.New(), Engine: "postgres", DiscoveryConfig: discoveryConfig})
		if err != nil {
			t.Fatalf("AdapterConfig: %v", err)
		}
		if len(cfg.Attributes) != 0 {
			t.Errorf("attributes for %s = %v, want empty", discoveryConfig, cfg.Attributes)
		}
	}
}

// TestEngineIdentityUnknownEngine фиксирует fallback: незарегистрированный
// в процессе adapter оставляет базовое имя как есть.
func TestEngineIdentityUnknownEngine(t *testing.T) {
	got, err := EngineIdentity(Connection{ID: uuid.New(), Engine: "nope"}, "e2e_global")
	if err != nil {
		t.Fatalf("EngineIdentity: %v", err)
	}
	if got != "e2e_global" {
		t.Errorf("EngineIdentity = %q, want e2e_global", got)
	}
}
