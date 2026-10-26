package adapter

import "testing"

// Отсутствие ключа означает «действует»: движок, который различия между
// «грант есть» и «грант работает» не делает, ничего сообщать не обязан.
func TestBindingEffectiveDefaults(t *testing.T) {
	if !BindingEffective(nil) {
		t.Error("BindingEffective(nil) = false, want true")
	}
	if !BindingEffective(map[string]any{"other": 1}) {
		t.Error("BindingEffective without the key = false, want true")
	}
	if BindingEffective(map[string]any{AttrBindingEffective: false}) {
		t.Error("BindingEffective(false) = true, want false")
	}
	if !BindingEffective(map[string]any{AttrBindingEffective: true}) {
		t.Error("BindingEffective(true) = false, want true")
	}
	// Нестрого типизированный атрибут не должен превращаться в «не работает»:
	// это скрыло бы реальный доступ за ложным дрифтом.
	if !BindingEffective(map[string]any{AttrBindingEffective: "yes"}) {
		t.Error("BindingEffective with a non-bool value = false, want true")
	}
}
