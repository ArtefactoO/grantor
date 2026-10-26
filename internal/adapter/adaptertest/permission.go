package adaptertest

import (
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Контрактные проверки нормализации прав. Нормализация — чистая функция от
// метаданных, поэтому проверки живут на уровне unit-тестов и не требуют
// поднятого движка: каждый адаптер вызывает CheckPermissionNormalization со
// своими реальными нотациями.
//
// Смысл контракта — гарантия, ради которой нормализация и делалась: право
// любого движка всегда можно прочитать целиком. Поэтому главный инвариант —
// Raw непуст и содержит исходное имя. Остальные поля адаптер вправе не
// заполнять, если они к его нотации неприменимы.

// knownCategories — категории, которые понимает UI. Адаптер, вернувший
// что-то иное, получит в интерфейсе неизвестную группу, поэтому набор
// проверяется явно.
var knownCategories = map[adapter.PermissionCategory]bool{
	adapter.PermissionRole:      true,
	adapter.PermissionPrivilege: true,
	adapter.PermissionACL:       true,
	adapter.PermissionBundle:    true,
	adapter.PermissionTag:       true,
	adapter.PermissionVhost:     true,
	adapter.PermissionTopic:     true,
	adapter.PermissionUnknown:   true,
}

// CheckPermissionNormalization проверяет инварианты представления одного
// права. Вызывается адаптером для каждой своей нотации.
func CheckPermissionNormalization(t *testing.T, ad adapter.Adapter, ref adapter.PermissionRef) adapter.PermissionView {
	t.Helper()
	n, ok := ad.(adapter.PermissionNormalizer)
	if !ok {
		t.Fatal("adapter does not implement adapter.PermissionNormalizer")
	}
	view := n.NormalizePermission(ref)

	// Право обязано остаться читаемым целиком: это и есть цель контракта.
	if view.Raw == "" {
		t.Errorf("NormalizePermission(%q): empty Raw", ref.Name)
	}
	if ref.Name != "" && !strings.Contains(view.Raw, ref.Name) {
		t.Errorf("NormalizePermission(%q): Raw = %q, want it to contain the original name",
			ref.Name, view.Raw)
	}
	if !knownCategories[view.Category] {
		t.Errorf("NormalizePermission(%q): unknown category %q", ref.Name, view.Category)
	}
	// Опасность и её объяснение существуют только вместе: причина без флага
	// вводит в заблуждение, флаг без причины бесполезен оператору.
	if view.Dangerous && view.DangerReason == "" {
		t.Errorf("NormalizePermission(%q): dangerous permission without a reason", ref.Name)
	}
	if !view.Dangerous && view.DangerReason != "" {
		t.Errorf("NormalizePermission(%q): danger reason %q on a permission that is not dangerous",
			ref.Name, view.DangerReason)
	}
	if view.Dangerous != ref.Dangerous {
		t.Errorf("NormalizePermission(%q): Dangerous = %v, want %v (must mirror the definition)",
			ref.Name, view.Dangerous, ref.Dangerous)
	}
	for i, d := range view.Details {
		if d.Key == "" || d.Value == "" {
			t.Errorf("NormalizePermission(%q): details[%d] = %+v, want both key and value", ref.Name, i, d)
		}
	}
	return view
}

// CheckPermissionNormalizationDegrades проверяет, что нераспознанная нотация
// не теряется. Исторические записи и записи, созданные другой версией
// адаптера, обязаны оставаться видимыми — молчаливое исчезновение права из
// интерфейса опаснее некрасивой подписи.
func CheckPermissionNormalizationDegrades(t *testing.T, ad adapter.Adapter) {
	t.Helper()
	ref := adapter.PermissionRef{
		ExternalID: "unrecognized:notation",
		Name:       "unrecognized-permission-name",
	}
	view := CheckPermissionNormalization(t, ad, ref)
	if view.Raw != ref.Name {
		t.Errorf("unrecognized notation: Raw = %q, want the name as is", view.Raw)
	}
}
