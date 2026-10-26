package adapter

import "testing"

// normalizingAdapter реализует опциональный контракт; stubAdapter — нет.
type normalizingAdapter struct{ stubAdapter }

func (normalizingAdapter) NormalizePermission(ref PermissionRef) PermissionView {
	return PermissionView{Category: PermissionRole, Resource: ref.Name, Raw: ref.Name}
}

// forgetfulAdapter нарушает контракт и не заполняет Raw. Ядро обязано это
// пережить: без Raw пользователь остался бы без исходного значения права —
// ровно той гарантии, ради которой нормализация и вводилась.
type forgetfulAdapter struct{ stubAdapter }

func (forgetfulAdapter) NormalizePermission(PermissionRef) PermissionView {
	return PermissionView{Category: PermissionRole}
}

func TestNormalizePermissionDispatch(t *testing.T) {
	Register("itest-perm-normalizing", func() Adapter { return normalizingAdapter{} })
	Register("itest-perm-plain", func() Adapter { return stubAdapter{} })
	Register("itest-perm-forgetful", func() Adapter { return forgetfulAdapter{} })

	ref := PermissionRef{ExternalID: "role:app", Name: "app", ScopeName: "ads"}

	t.Run("adapter with a normalizer", func(t *testing.T) {
		got := NormalizePermission("itest-perm-normalizing", ref)
		if got.Category != PermissionRole || got.Raw != "app" {
			t.Errorf("view = %+v, want the adapter's own normalization", got)
		}
	})

	// Движок без нормализатора и незарегистрированный движок не должны
	// приводить к исчезновению права из выдачи.
	for _, engine := range []string{"itest-perm-plain", "itest-perm-missing"} {
		t.Run("generic fallback for "+engine, func(t *testing.T) {
			got := NormalizePermission(engine, ref)
			if got.Category != PermissionUnknown {
				t.Errorf("Category = %q, want unknown", got.Category)
			}
			if got.Raw != "app @ ads" {
				t.Errorf("Raw = %q, want the full expression", got.Raw)
			}
		})
	}

	t.Run("missing Raw is filled in by the core", func(t *testing.T) {
		got := NormalizePermission("itest-perm-forgetful", ref)
		if got.Raw != "app @ ads" {
			t.Errorf("Raw = %q, want the core to fill it in", got.Raw)
		}
	})
}

func TestRawPermissionExpression(t *testing.T) {
	cases := []struct {
		name string
		ref  PermissionRef
		want string
	}{
		{"no scope", PermissionRef{Name: "app_ro"}, "app_ro"},
		{"scope appended", PermissionRef{Name: "readWrite", ScopeName: "ads"}, "readWrite @ ads"},
		// Паттерн адаптеров `<verb>:<scope>` — повтор scope только удлиняет
		// строку, ничего не добавляя.
		{"scope already in the name", PermissionRef{Name: "vhost-access:sl", ScopeName: "sl"}, "vhost-access:sl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RawPermissionExpression(tc.ref); got != tc.want {
				t.Errorf("RawPermissionExpression = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAttributeDetails(t *testing.T) {
	// kind уже выражен категорией и в детали не попадает; пустые значения
	// отбрасываются; порядок стабилен, иначе панель переставляла бы строки
	// между запросами.
	details := AttributeDetails(map[string]any{
		"kind":    "role",
		"zulu":    "last",
		"alpha":   true,
		"count":   float64(3),
		"nothing": nil,
		"list":    []any{"a", "b"},
	})
	want := []PermissionDetail{
		{Key: "alpha", Value: "true"},
		{Key: "count", Value: "3"},
		{Key: "list", Value: "a, b"},
		{Key: "zulu", Value: "last"},
	}
	if len(details) != len(want) {
		t.Fatalf("details = %+v, want %+v", details, want)
	}
	for i := range want {
		if details[i] != want[i] {
			t.Errorf("details[%d] = %+v, want %+v", i, details[i], want[i])
		}
	}
}

func TestAttrStringsAcceptsJSONShape(t *testing.T) {
	// Из свежего discovery атрибут приходит как []string, из БД — как []any.
	attrs := map[string]any{"fromGo": []string{"a"}, "fromJSON": []any{"b", 1}}
	if got := AttrStrings(attrs, "fromGo"); len(got) != 1 || got[0] != "a" {
		t.Errorf("AttrStrings([]string) = %v, want [a]", got)
	}
	if got := AttrStrings(attrs, "fromJSON"); len(got) != 1 || got[0] != "b" {
		t.Errorf("AttrStrings([]any) = %v, want [b] (non-strings skipped)", got)
	}
}
