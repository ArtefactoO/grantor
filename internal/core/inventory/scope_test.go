package inventory

import (
	"testing"

	"github.com/google/uuid"
)

// TestEffectiveBindingScope закрывает все четыре комбинации «область задана в
// запросе / у permission-определения»: наследование срабатывает ровно тогда,
// когда оператор область не указал.
func TestEffectiveBindingScope(t *testing.T) {
	topic := uuid.New()
	other := uuid.New()

	tests := []struct {
		name      string
		permScope *uuid.UUID
		requested *uuid.UUID
		want      *uuid.UUID
	}{
		{
			name: "cluster-wide permission without request stays unscoped",
		},
		{
			name:      "scoped permission without request inherits its own scope",
			permScope: &topic,
			want:      &topic,
		},
		{
			name:      "explicit request wins over cluster-wide permission",
			requested: &other,
			want:      &other,
		},
		{
			name:      "explicit request equal to permission scope is preserved",
			permScope: &topic,
			requested: &topic,
			want:      &topic,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := Permission{ID: uuid.New(), ScopeResourceID: tt.permScope}
			got := EffectiveBindingScope(perm, tt.requested)
			if !SameScope(got, tt.want) {
				t.Fatalf("EffectiveBindingScope = %v, want %v", got, tt.want)
			}
			// Идемпотентность: повторный вывод поверх результата его не меняет.
			if again := EffectiveBindingScope(perm, got); !SameScope(again, got) {
				t.Fatalf("EffectiveBindingScope is not idempotent: %v then %v", got, again)
			}
		})
	}
}

// TestScopeConflicts проверяет, что противоречие фиксируется только при
// явно заданной чужой области у permission с собственной областью.
func TestScopeConflicts(t *testing.T) {
	topic := uuid.New()
	other := uuid.New()

	tests := []struct {
		name      string
		permScope *uuid.UUID
		requested *uuid.UUID
		want      bool
	}{
		{name: "nothing requested, nothing defined"},
		{name: "inheritance is not a conflict", permScope: &topic},
		{name: "cluster-wide permission accepts any requested scope", requested: &other},
		{name: "same scope is not a conflict", permScope: &topic, requested: &topic},
		{name: "foreign scope on scoped permission conflicts", permScope: &topic, requested: &other, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := Permission{ID: uuid.New(), ScopeResourceID: tt.permScope}
			if got := ScopeConflicts(perm, tt.requested); got != tt.want {
				t.Fatalf("ScopeConflicts = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSameScopeComparesByValue фиксирует, что сравнение идёт по значению, а не
// по указателю: scope приходит из разных источников.
func TestSameScopeComparesByValue(t *testing.T) {
	id := uuid.New()
	a, b := id, id
	if !SameScope(&a, &b) {
		t.Error("SameScope = false for equal values in distinct pointers, want true")
	}
	if !SameScope(nil, nil) {
		t.Error("SameScope(nil, nil) = false, want true")
	}
	if SameScope(&a, nil) || SameScope(nil, &a) {
		t.Error("SameScope with a single nil = true, want false")
	}
	other := uuid.New()
	if SameScope(&a, &other) {
		t.Error("SameScope = true for different values, want false")
	}
}

// TestBindingHasPermissionScope проверяет отбор bindings, выражающих право
// целиком: суженный оператором до чужого ресурса binding таковым не является.
func TestBindingHasPermissionScope(t *testing.T) {
	topic := uuid.New()
	other := uuid.New()
	scoped := Permission{ID: uuid.New(), ScopeResourceID: &topic}
	clusterWide := Permission{ID: uuid.New()}

	if !BindingHasPermissionScope(Binding{ScopeResourceID: &topic}, scoped) {
		t.Error("binding on permission scope not recognized")
	}
	if BindingHasPermissionScope(Binding{ScopeResourceID: &other}, scoped) {
		t.Error("binding on foreign scope recognized as permission scope")
	}
	if BindingHasPermissionScope(Binding{}, scoped) {
		t.Error("unscoped binding recognized as scope of a scoped permission")
	}
	if !BindingHasPermissionScope(Binding{}, clusterWide) {
		t.Error("unscoped binding not recognized for cluster-wide permission")
	}
	if BindingHasPermissionScope(Binding{ScopeResourceID: &topic}, clusterWide) {
		t.Error("scoped binding recognized for cluster-wide permission")
	}
}
