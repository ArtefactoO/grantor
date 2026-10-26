package adapter

import (
	"slices"
	"testing"
)

// manifestAdapter — заглушка с фиксированным манифестом и без опционального
// контракта сужения.
type manifestAdapter struct {
	stubAdapter
	caps []Capability
}

func (a manifestAdapter) Manifest() Manifest {
	return Manifest{Engine: "itest-caps", Capabilities: a.caps}
}

// scopingAdapter реализует ConnectionCapabilityScoper: убирает lifecycle на
// «неподходящем» подключении и ACL-операции при наблюдаемом ограничении.
type scopingAdapter struct{ manifestAdapter }

func (a scopingAdapter) CapabilitiesFor(cfg Connection, topology map[string]any) []Capability {
	out := []Capability{CapInventoryResources}
	if cfg.Attributes["mechanism"] == "scram" {
		out = append(out, CapAccountCreate, CapCredentialRotate)
	}
	if topology["authorizer"] != "disabled" {
		out = append(out, CapAccessGrant)
	}
	// Заведомо чужая capability: контракт обязывает ядро её отбросить.
	return append(out, CapAccountRestore)
}

func TestCapabilitiesForScoping(t *testing.T) {
	manifest := []Capability{
		CapInventoryResources, CapAccessGrant, CapAccountCreate, CapCredentialRotate,
	}
	Register("itest-caps-scoping", func() Adapter {
		return scopingAdapter{manifestAdapter{caps: manifest}}
	})
	Register("itest-caps-plain", func() Adapter {
		return manifestAdapter{caps: manifest}
	})

	cases := []struct {
		name     string
		engine   string
		attrs    map[string]any
		topology map[string]any
		want     []Capability
	}{
		{
			name: "scram connection keeps lifecycle", engine: "itest-caps-scoping",
			attrs: map[string]any{"mechanism": "scram"},
			want:  manifest,
		},
		{
			name: "non-scram connection loses lifecycle", engine: "itest-caps-scoping",
			attrs: map[string]any{"mechanism": "plain"},
			want:  []Capability{CapInventoryResources, CapAccessGrant},
		},
		{
			name: "observed topology narrows further", engine: "itest-caps-scoping",
			attrs:    map[string]any{"mechanism": "plain"},
			topology: map[string]any{"authorizer": "disabled"},
			want:     []Capability{CapInventoryResources},
		},
		{
			name: "adapter without the contract keeps the manifest", engine: "itest-caps-plain",
			want: manifest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CapabilitiesFor(Connection{
				Engine:     tc.engine,
				Attributes: tc.attrs,
			}, tc.topology)
			if err != nil {
				t.Fatalf("CapabilitiesFor: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("CapabilitiesFor = %v, want %v", got, tc.want)
			}
			// Результат обязан быть подмножеством манифеста в его порядке:
			// adapter не может через этот путь расширить свои возможности.
			if slices.Contains(got, CapAccountRestore) {
				t.Error("capability outside the manifest must be dropped")
			}
		})
	}
}

func TestCapabilitiesForUnknownEngine(t *testing.T) {
	if _, err := CapabilitiesFor(Connection{Engine: "itest-caps-missing"}, nil); err == nil {
		t.Fatal("CapabilitiesFor for an unregistered engine: err = nil, want error")
	}
}

func TestCapabilityNames(t *testing.T) {
	got := CapabilityNames([]Capability{CapAccessGrant, CapAccessRevoke})
	if !slices.Equal(got, []string{"access.grant", "access.revoke"}) {
		t.Errorf("CapabilityNames = %v", got)
	}
	m := Manifest{Capabilities: []Capability{CapInventoryAccounts}}
	if !slices.Equal(m.CapabilityNames(), []string{"inventory.accounts"}) {
		t.Errorf("Manifest.CapabilityNames = %v", m.CapabilityNames())
	}
}
