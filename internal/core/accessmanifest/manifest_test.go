package accessmanifest

import "testing"

func TestManifestValidate(t *testing.T) {
	base := func() Manifest {
		return Manifest{
			Version: "v1",
			Entries: []Entry{{Principal: "svc", Connection: "conn", Role: "role:ro"}},
		}
	}

	cases := []struct {
		name    string
		mutate  func(m *Manifest)
		wantErr bool
	}{
		{name: "valid present default", mutate: func(*Manifest) {}, wantErr: false},
		{name: "valid explicit absent", mutate: func(m *Manifest) { m.Entries[0].State = string(StateAbsent) }, wantErr: false},
		{name: "empty entries ok", mutate: func(m *Manifest) { m.Entries = nil }, wantErr: false},
		{name: "wrong version", mutate: func(m *Manifest) { m.Version = "v2" }, wantErr: true},
		{name: "empty version", mutate: func(m *Manifest) { m.Version = "" }, wantErr: true},
		{name: "missing principal", mutate: func(m *Manifest) { m.Entries[0].Principal = "  " }, wantErr: true},
		{name: "missing connection", mutate: func(m *Manifest) { m.Entries[0].Connection = "" }, wantErr: true},
		{name: "missing role", mutate: func(m *Manifest) { m.Entries[0].Role = "" }, wantErr: true},
		{name: "invalid state", mutate: func(m *Manifest) { m.Entries[0].State = "maybe" }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(&m)
			err := m.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestManifestValidateEntryLimit(t *testing.T) {
	m := Manifest{Version: "v1"}
	for i := 0; i <= maxEntries; i++ {
		m.Entries = append(m.Entries, Entry{Principal: "p", Connection: "c", Role: "r"})
	}
	if err := m.Validate(); err == nil {
		t.Fatalf("Validate() with %d entries = nil, want error", len(m.Entries))
	}
}

func TestEntryStateOrDefault(t *testing.T) {
	if got := (Entry{}).stateOrDefault(); got != StatePresent {
		t.Errorf("empty state = %q, want %q", got, StatePresent)
	}
	if got := (Entry{State: "absent"}).stateOrDefault(); got != StateAbsent {
		t.Errorf("absent state = %q, want %q", got, StateAbsent)
	}
}
