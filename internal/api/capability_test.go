package api

import (
	"context"
	"sync"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// capTestEngine — движок-заглушка только для этого теста: имя уникально,
// поэтому регистрация не конфликтует с реальными adapters, которые
// integration-тесты пакета регистрируют в том же процессе.
const capTestEngine = "captest-limited"

var registerCapTestOnce sync.Once

// capTestAdapter объявляет ровно одну capability: этого достаточно, чтобы
// проверить обе ветки engineSupports без реального движка.
type capTestAdapter struct{}

func (capTestAdapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:       capTestEngine,
		Capabilities: []adapter.Capability{adapter.CapInventoryAccounts},
	}
}

func (capTestAdapter) ValidateConnection(context.Context, adapter.Connection) error { return nil }

func (capTestAdapter) Discover(context.Context, adapter.Connection) (*adapter.Snapshot, error) {
	return &adapter.Snapshot{}, nil
}

func (capTestAdapter) Plan(context.Context, adapter.DesiredChange) (*adapter.Plan, error) {
	return nil, adapter.ErrUnsupportedChange
}

func (capTestAdapter) Apply(context.Context, adapter.Plan) (*adapter.Result, error) {
	return nil, adapter.ErrUnsupportedChange
}

func (capTestAdapter) Verify(context.Context, adapter.Plan) (*adapter.Verification, error) {
	return nil, adapter.ErrUnsupportedChange
}

func (capTestAdapter) GenerateCredential(context.Context, adapter.CredentialPolicy) (*adapter.Credential, error) {
	return &adapter.Credential{}, nil
}

func (capTestAdapter) RotateCredential(context.Context, adapter.Connection, adapter.Account, adapter.Credential) error {
	return adapter.ErrUnsupportedChange
}

// TestEngineSupports: объявленная capability разрешает операцию, не
// объявленная — запрещает, а неизвестный движок не даёт API отказывать по
// незнанию (решение остаётся за worker).
func TestEngineSupports(t *testing.T) {
	registerCapTestOnce.Do(func() {
		adapter.Register(capTestEngine, func() adapter.Adapter { return capTestAdapter{} })
	})

	if !engineSupports(capTestEngine, adapter.CapInventoryAccounts) {
		t.Error("declared capability must be supported")
	}
	if engineSupports(capTestEngine, adapter.CapAccessGrant) {
		t.Error("capability missing from the manifest must not be supported")
	}
	if !engineSupports("captest-unregistered", adapter.CapAccessGrant) {
		t.Error("unregistered engine must not be rejected by the API")
	}
}

// capProverEngine — второй движок-заглушка: тот же манифест, но с
// реализацией adapter.CredentialProver. Разница между ним и capTestEngine —
// ровно то, что различает engineProvesCredential.
const capProverEngine = "captest-prover"

var registerCapProverOnce sync.Once

type capProverAdapter struct{ capTestAdapter }

func (capProverAdapter) ProveCredential(context.Context, adapter.Connection, adapter.Account, adapter.Credential) error {
	return nil
}

// TestEngineProvesCredential: adopt mode=verify_password допускается только на
// движке, реализующем adapter.CredentialProver. Неизвестный движок здесь —
// НЕумеющий (в отличие от engineSupports): иначе API принял бы запрос, положил
// проверяемый пароль в Vault и лишь потом получил отказ worker.
func TestEngineProvesCredential(t *testing.T) {
	registerCapTestOnce.Do(func() {
		adapter.Register(capTestEngine, func() adapter.Adapter { return capTestAdapter{} })
	})
	registerCapProverOnce.Do(func() {
		adapter.Register(capProverEngine, func() adapter.Adapter { return capProverAdapter{} })
	})

	if !engineProvesCredential(capProverEngine) {
		t.Error("engine implementing CredentialProver must be able to prove a password")
	}
	if engineProvesCredential(capTestEngine) {
		t.Error("engine without CredentialProver must not be able to prove a password")
	}
	if engineProvesCredential("captest-unregistered") {
		t.Error("unregistered engine must not be treated as able to prove a password")
	}
}
