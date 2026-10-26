package auth

import (
	"slices"
	"testing"
)

// Маппинг ролей по группам IdP. Порядок разрешения существенен: явное
// назначение персоне через email должно побеждать её членство в группе,
// иначе точечно понизить человека было бы невозможно.
func TestRoleForGroups(t *testing.T) {
	a := &Authenticator{
		admins:         emailSet([]string{"boss@example.com"}),
		viewers:        emailSet([]string{"demoted@example.com"}),
		adminGroups:    emailSet([]string{"grantor-admins"}),
		operatorGroups: emailSet([]string{"grantor-operators"}),
		viewerGroups:   emailSet([]string{"grantor-viewers"}),
	}

	cases := []struct {
		name   string
		email  string
		groups []string
		want   Role
		ok     bool
	}{
		{name: "group grants admin", email: "a@example.com",
			groups: []string{"grantor-admins"}, want: RoleAdmin, ok: true},
		{name: "group grants operator", email: "b@example.com",
			groups: []string{"other", "grantor-operators"}, want: RoleOperator, ok: true},
		// Регистр имён групп в AD не значим.
		{name: "group match ignores case", email: "c@example.com",
			groups: []string{"GRANTOR-Admins"}, want: RoleAdmin, ok: true},
		// Несколько групп — берётся старшая роль.
		{name: "highest role wins", email: "d@example.com",
			groups: []string{"grantor-viewers", "grantor-admins"}, want: RoleAdmin, ok: true},
		// Явный список email сильнее группы: и вверх, и вниз.
		{name: "email list beats group", email: "demoted@example.com",
			groups: []string{"grantor-admins"}, want: RoleViewer, ok: true},
		{name: "email admin without groups", email: "boss@example.com",
			groups: nil, want: RoleAdmin, ok: true},
		// Без совпадений и без DefaultRole — вход запрещён.
		{name: "no match denies login", email: "stranger@example.com",
			groups: []string{"unrelated"}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := a.roleFor(tc.email, tc.groups)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("role = %q, want %q", got, tc.want)
			}
		})
	}
}

// Scope groups запрашивается только когда группы настроены: лишний scope у
// IdP, который его не знает, приводит к отказу в выдаче токена — то есть
// сломал бы вход всем.
func TestScopesRequestGroupsOnlyWhenConfigured(t *testing.T) {
	if got := scopes(Config{}); slices.Contains(got, "groups") {
		t.Errorf("scopes without group mapping = %v, want no groups scope", got)
	}
	got := scopes(Config{OperatorGroups: []string{"grantor-operators"}})
	if !slices.Contains(got, "groups") {
		t.Errorf("scopes with group mapping = %v, want the groups scope", got)
	}
}
