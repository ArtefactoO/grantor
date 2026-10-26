package fake_test

import (
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
)

func TestContract(t *testing.T) {
	adaptertest.Run(t, adaptertest.Harness{
		New: func(_ *testing.T) (adapter.Adapter, adapter.Connection) {
			return fake.New(), adapter.Connection{
				ID:        "conn-fake",
				Engine:    fake.Engine,
				Endpoints: []string{"fake://localhost"},
				AdminCredential: adapter.Credential{
					Kind:     "password",
					Username: "admin",
					Secret:   []byte("s3cr3t-admin-password"),
				},
			}
		},
	})
}

func TestRegistry(t *testing.T) {
	adapter.Register(fake.Engine, func() adapter.Adapter { return fake.New() })

	ad, err := adapter.New(fake.Engine)
	if err != nil {
		t.Fatalf("New(%q): %v", fake.Engine, err)
	}
	if got := ad.Manifest().Engine; got != fake.Engine {
		t.Errorf("Manifest().Engine = %q, want %q", got, fake.Engine)
	}
	if !slices.Contains(adapter.Engines(), fake.Engine) {
		t.Errorf("Engines() = %v, want to contain %q", adapter.Engines(), fake.Engine)
	}
	if _, err := adapter.New("unknown-engine"); err == nil {
		t.Error("New(unknown-engine): expected error")
	}
}
