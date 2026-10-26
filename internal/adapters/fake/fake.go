// Package fake реализует in-memory adapter для contract suite и тестов ядра.
// В production-сборки worker/connector не подключается.
package fake

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Engine — имя движка fake adapter.
const Engine = "fake"

type bindingKey struct {
	account    string
	permission string
	scope      string
}

// Fake реализует adapter.Adapter поверх изменяемого in-memory состояния,
// засеянного фикстурой: database app со schema public, аккаунты svc-a (login)
// и readers (group), роли app-readonly/app-readwrite/superuser.
type Fake struct {
	mu          sync.Mutex
	resources   []adapter.ObservedResource
	accounts    map[string]adapter.ObservedAccount
	permissions []adapter.ObservedPermission
	bindings    map[bindingKey]struct{}
	credentials map[string][]byte
}

var _ adapter.Adapter = (*Fake)(nil)
var _ adapter.CredentialProver = (*Fake)(nil)

// New возвращает fake adapter с засеянной фикстурой.
func New() *Fake {
	f := &Fake{
		accounts:    map[string]adapter.ObservedAccount{},
		bindings:    map[bindingKey]struct{}{},
		credentials: map[string][]byte{},
	}
	f.resources = []adapter.ObservedResource{
		{Kind: "database", ExternalID: "db:app", Name: "app", CanonicalPath: "app", Fingerprint: "fp-db-app"},
		{Kind: "schema", ExternalID: "schema:app.public", ParentExternalID: "db:app", Name: "public", CanonicalPath: "app.public", Fingerprint: "fp-schema-public"},
	}
	f.accounts["svc-a"] = adapter.ObservedAccount{Kind: "login", EngineIdentity: "svc-a"}
	f.accounts["readers"] = adapter.ObservedAccount{Kind: "group", EngineIdentity: "readers"}
	f.permissions = []adapter.ObservedPermission{
		{ExternalID: "role:app-readonly", Name: "app-readonly", Assignable: true},
		{ExternalID: "role:app-readwrite", Name: "app-readwrite", Assignable: true},
		{ExternalID: "role:superuser", Name: "superuser", Assignable: true, Dangerous: true},
	}
	f.bindings[bindingKey{account: "readers", permission: "role:app-readonly"}] = struct{}{}
	return f
}

func (f *Fake) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:        Engine,
		Version:       "v1",
		ResourceKinds: []string{"database", "schema"},
		Capabilities: []adapter.Capability{
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccountCreate,
			adapter.CapRoleCreate,
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			adapter.CapAccountRestore,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.ResourceCapability("create", "database"),
		},
		ConnectionSchema: "fake-connection-v1",
	}
}

func (f *Fake) ValidateConnection(_ context.Context, cfg adapter.Connection) error {
	if len(cfg.Endpoints) == 0 {
		return fmt.Errorf("fake: no endpoints configured")
	}
	if len(cfg.AdminCredential.Secret) == 0 {
		return fmt.Errorf("fake: admin credential is empty")
	}
	return nil
}

func (f *Fake) Discover(_ context.Context, _ adapter.Connection) (*adapter.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	snap := &adapter.Snapshot{
		ServerVersion: "fake-1.0",
		ObservedAt:    time.Now(),
		Resources:     slices.Clone(f.resources),
		Permissions:   slices.Clone(f.permissions),
	}
	for _, a := range f.accounts {
		snap.Accounts = append(snap.Accounts, a)
	}
	slices.SortFunc(snap.Accounts, func(a, b adapter.ObservedAccount) int {
		return strings.Compare(a.EngineIdentity, b.EngineIdentity)
	})
	for k := range f.bindings {
		snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
			AccountEngineIdentity: k.account,
			PermissionExternalID:  k.permission,
			ScopeExternalID:       k.scope,
		})
	}
	slices.SortFunc(snap.Bindings, func(a, b adapter.ObservedBinding) int {
		if c := strings.Compare(a.AccountEngineIdentity, b.AccountEngineIdentity); c != 0 {
			return c
		}
		return strings.Compare(a.PermissionExternalID, b.PermissionExternalID)
	})
	return snap, nil
}

func (f *Fake) Plan(_ context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		if _, ok := f.accounts[change.Account.EngineIdentity]; !ok {
			return nil, fmt.Errorf("account %q: %w", change.Account.EngineIdentity, adapter.ErrNotFound)
		}
		if !f.permissionExists(change.Permission) {
			return nil, fmt.Errorf("permission %q: %w", change.Permission, adapter.ErrNotFound)
		}
		verb := "grant"
		if change.Kind == adapter.ChangeRevoke {
			verb = "revoke"
		}
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        verb,
				Description: fmt.Sprintf("%s %s -> %s", verb, change.Permission, change.Account.EngineIdentity),
			}},
		}, nil
	case adapter.ChangeAccountCreate:
		// Тот же контракт, что у настоящих adapters: account.create создаёт
		// новую identity и никогда не присваивает существующую.
		if _, exists := f.accounts[change.Account.EngineIdentity]; exists {
			return nil, fmt.Errorf("fake: plan account.create: account %q already exists: %w",
				change.Account.EngineIdentity, adapter.ErrExternalIdentityConflict)
		}
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        string(change.Kind),
				Description: fmt.Sprintf("%s account %s", change.Kind, change.Account.EngineIdentity),
			}},
		}, nil
	case adapter.ChangeRoleCreate:
		// Роль без логина — та же защита от захвата чужой identity, что у
		// account.create: она видна и как account, и как назначаемое право,
		// поэтому проверяются обе проекции.
		if _, exists := f.accounts[change.Account.EngineIdentity]; exists {
			return nil, fmt.Errorf("fake: plan role.create: account %q already exists: %w",
				change.Account.EngineIdentity, adapter.ErrExternalIdentityConflict)
		}
		if f.permissionExists("role:" + change.Account.EngineIdentity) {
			return nil, fmt.Errorf("fake: plan role.create: role %q already exists: %w",
				change.Account.EngineIdentity, adapter.ErrExternalIdentityConflict)
		}
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        string(change.Kind),
				Description: fmt.Sprintf("create group role %s (nologin)", change.Account.EngineIdentity),
			}},
		}, nil
	case adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete:
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        string(change.Kind),
				Description: fmt.Sprintf("%s account %s", change.Kind, change.Account.EngineIdentity),
			}},
		}, nil
	case adapter.ChangeAccountRestore:
		if change.Credential == nil || len(change.Credential.Secret) == 0 {
			return nil, fmt.Errorf("fake: plan account.restore: credential is required")
		}
		if _, exists := f.accounts[change.Account.EngineIdentity]; exists {
			if !slices.Equal(f.credentials[change.Account.EngineIdentity], change.Credential.Secret) {
				return nil, fmt.Errorf("fake: plan account.restore: %w", adapter.ErrExternalIdentityConflict)
			}
		}
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        string(change.Kind),
				Description: fmt.Sprintf("restore account %s with credential proof", change.Account.EngineIdentity),
			}},
		}, nil
	case adapter.ChangeResourceCreate:
		if change.Resource == nil || change.Resource.Kind != "database" {
			return nil, adapter.ErrUnsupportedChange
		}
		// Существующая база не присваивается: захват чужого объекта в
		// инвентарь необратим — отката у создания базы нет.
		if f.resourceExists("database", change.Resource.Name) {
			return nil, fmt.Errorf("fake: plan resource.create: database %q already exists: %w",
				change.Resource.Name, adapter.ErrExternalIdentityConflict)
		}
		return &adapter.Plan{
			Change: change,
			Steps: []adapter.PlanStep{{
				Kind:        "resource.create.database",
				Description: "create database " + change.Resource.Name,
			}},
		}, nil
	default:
		return nil, adapter.ErrUnsupportedChange
	}
}

func (f *Fake) Apply(_ context.Context, plan adapter.Plan) (*adapter.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	res := &adapter.Result{}
	for _, step := range plan.Steps {
		res.Steps = append(res.Steps, adapter.StepResult{
			Step:   step,
			Status: f.applyStep(plan.Change, step),
		})
	}
	return res, nil
}

func (f *Fake) applyStep(change adapter.DesiredChange, step adapter.PlanStep) adapter.StepStatus {
	identity := change.Account.EngineIdentity
	key := bindingKey{account: identity, permission: change.Permission, scope: change.Scope}
	switch step.Kind {
	case "grant":
		if _, ok := f.bindings[key]; ok {
			return adapter.StepSkipped
		}
		f.bindings[key] = struct{}{}
		return adapter.StepApplied
	case "revoke":
		if _, ok := f.bindings[key]; !ok {
			return adapter.StepSkipped
		}
		delete(f.bindings, key)
		return adapter.StepApplied
	case string(adapter.ChangeAccountCreate):
		if _, ok := f.accounts[identity]; ok {
			// Identity появилась между Plan и Apply — присваивать её нельзя.
			return adapter.StepFailed
		}
		f.accounts[identity] = adapter.ObservedAccount{Kind: "login", EngineIdentity: identity}
		if change.Credential != nil {
			f.credentials[identity] = slices.Clone(change.Credential.Secret)
		}
		return adapter.StepApplied
	case string(adapter.ChangeRoleCreate):
		if _, ok := f.accounts[identity]; ok {
			// Роль появилась между Plan и Apply — присваивать её нельзя.
			return adapter.StepFailed
		}
		f.accounts[identity] = adapter.ObservedAccount{Kind: "group", EngineIdentity: identity}
		// Роль без логина публикуется и как назначаемое право: ровно так её
		// видит discovery настоящего движка.
		f.permissions = append(f.permissions, adapter.ObservedPermission{
			ExternalID:            "role:" + identity,
			Name:                  identity,
			Assignable:            true,
			AccountEngineIdentity: identity,
		})
		return adapter.StepApplied
	case string(adapter.ChangeAccountRestore):
		if _, ok := f.accounts[identity]; ok {
			if slices.Equal(f.credentials[identity], change.Credential.Secret) {
				return adapter.StepSkipped
			}
			return adapter.StepFailed
		}
		f.accounts[identity] = adapter.ObservedAccount{Kind: "login", EngineIdentity: identity}
		f.credentials[identity] = slices.Clone(change.Credential.Secret)
		return adapter.StepApplied
	case string(adapter.ChangeAccountDisable), string(adapter.ChangeAccountEnable):
		a, ok := f.accounts[identity]
		if !ok {
			return adapter.StepFailed
		}
		disabled := step.Kind == string(adapter.ChangeAccountDisable)
		if a.Disabled == disabled {
			return adapter.StepSkipped
		}
		a.Disabled = disabled
		f.accounts[identity] = a
		return adapter.StepApplied
	case string(adapter.ChangeAccountDelete):
		if _, ok := f.accounts[identity]; !ok {
			return adapter.StepSkipped
		}
		delete(f.accounts, identity)
		delete(f.credentials, identity)
		for k := range f.bindings {
			if k.account == identity {
				delete(f.bindings, k)
			}
		}
		return adapter.StepApplied
	case "resource.create.database":
		externalID := "db:" + change.Resource.Name
		for _, r := range f.resources {
			if r.ExternalID == externalID {
				// База появилась между Plan и Apply — присваивать её нельзя.
				return adapter.StepFailed
			}
		}
		f.resources = append(f.resources, adapter.ObservedResource{
			Kind:          "database",
			ExternalID:    externalID,
			Name:          change.Resource.Name,
			CanonicalPath: change.Resource.Name,
			Fingerprint:   "fp-" + externalID,
		})
		return adapter.StepApplied
	default:
		return adapter.StepFailed
	}
}

func (f *Fake) Verify(_ context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c := plan.Change
	identity := c.Account.EngineIdentity
	key := bindingKey{account: identity, permission: c.Permission, scope: c.Scope}
	switch c.Kind {
	case adapter.ChangeGrant:
		_, ok := f.bindings[key]
		return verification(ok, "binding present"), nil
	case adapter.ChangeRevoke:
		_, ok := f.bindings[key]
		return verification(!ok, "binding absent"), nil
	case adapter.ChangeAccountCreate:
		_, ok := f.accounts[identity]
		return verification(ok, "account exists"), nil
	case adapter.ChangeRoleCreate:
		a, ok := f.accounts[identity]
		// Роль обязана быть именно ролью: учётка с логином под тем же именем
		// означала бы, что применилось не то, что планировалось.
		return verification(ok && a.Kind == "group", "role exists and cannot log in"), nil
	case adapter.ChangeAccountRestore:
		a, ok := f.accounts[identity]
		proved := ok && !a.Disabled && c.Credential != nil && slices.Equal(f.credentials[identity], c.Credential.Secret)
		return verification(proved, "account exists and credential is proved"), nil
	case adapter.ChangeAccountDelete:
		_, ok := f.accounts[identity]
		return verification(!ok, "account removed"), nil
	case adapter.ChangeAccountDisable:
		a, ok := f.accounts[identity]
		return verification(ok && a.Disabled, "account disabled"), nil
	case adapter.ChangeAccountEnable:
		a, ok := f.accounts[identity]
		return verification(ok && !a.Disabled, "account enabled"), nil
	case adapter.ChangeResourceCreate:
		if c.Resource == nil {
			return nil, adapter.ErrUnsupportedChange
		}
		for _, r := range f.resources {
			if r.Kind == c.Resource.Kind && r.Name == c.Resource.Name {
				return verification(true, "resource exists"), nil
			}
		}
		return verification(false, "resource exists"), nil
	default:
		return nil, adapter.ErrUnsupportedChange
	}
}

func (f *Fake) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	n := policy.Length
	if n <= 0 {
		n = 24
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return &adapter.Credential{Kind: "password", Secret: []byte(hex.EncodeToString(buf)[:n])}, nil
}

func (f *Fake) RotateCredential(_ context.Context, _ adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.accounts[account.EngineIdentity]; !ok {
		return fmt.Errorf("account %q: %w", account.EngineIdentity, adapter.ErrNotFound)
	}
	f.credentials[account.EngineIdentity] = slices.Clone(credential.Secret)
	return nil
}

// ProveCredential доказывает владение fake identity точным совпадением с
// секретом в in-memory target. Никаких производных credential наружу не
// возвращается.
func (f *Fake) ProveCredential(_ context.Context, _ adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.accounts[account.EngineIdentity]; !ok {
		return fmt.Errorf("fake: prove credential: account %q: %w", account.EngineIdentity, adapter.ErrNotFound)
	}
	if !slices.Equal(f.credentials[account.EngineIdentity], credential.Secret) {
		return fmt.Errorf("fake: prove credential: %w", adapter.ErrExternalIdentityConflict)
	}
	return nil
}

// resourceExists сообщает, есть ли уже ресурс такого вида с таким именем.
func (f *Fake) resourceExists(kind, name string) bool {
	for _, r := range f.resources {
		if r.Kind == kind && r.Name == name {
			return true
		}
	}
	return false
}

func (f *Fake) permissionExists(externalID string) bool {
	for _, p := range f.permissions {
		if p.ExternalID == externalID {
			return true
		}
	}
	return false
}

func verification(ok bool, what string) *adapter.Verification {
	v := &adapter.Verification{Verified: ok}
	if ok {
		v.Details = "verified: " + what
	} else {
		v.Details = "not in expected state: " + what
	}
	return v
}
