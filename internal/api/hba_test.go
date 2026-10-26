package api

import (
	"encoding/json"
	"testing"
)

// Матчинг намеренно консервативный: ложное предупреждение о недоступности
// хуже отсутствия предупреждения — оно заставляет править работающую
// конфигурацию.
func TestRuleCoversUser(t *testing.T) {
	cases := []struct {
		name     string
		rule     hbaRule
		identity string
		memberOf []string
		want     bool
	}{
		{
			name:     "all покрывает любого",
			rule:     hbaRule{Users: []string{"all"}, AuthMethod: "scram-sha-256"},
			identity: "app_user", want: true,
		},
		{
			name:     "точное имя",
			rule:     hbaRule{Users: []string{"svc_bot", "app_user"}, AuthMethod: "md5"},
			identity: "app_user", want: true,
		},
		{
			name:     "чужое имя не покрывает",
			rule:     hbaRule{Users: []string{"svc_bot"}, AuthMethod: "md5"},
			identity: "app_user", want: false,
		},
		{
			name:     "+роль покрывает члена",
			rule:     hbaRule{Users: []string{"+app_read"}, AuthMethod: "md5"},
			identity: "app_user", memberOf: []string{"app_read"}, want: true,
		},
		{
			name:     "+роль не покрывает не-члена",
			rule:     hbaRule{Users: []string{"+app_write"}, AuthMethod: "md5"},
			identity: "app_user", memberOf: []string{"app_read"}, want: false,
		},
		{
			// Регулярное выражение не интерпретируется: предупреждать наугад
			// нельзя, поэтому считаем покрывающим.
			name:     "регулярное выражение считается покрывающим",
			rule:     hbaRule{Users: []string{"/^app_.*"}, AuthMethod: "md5"},
			identity: "app_user", want: true,
		},
		{
			name:     "reject не покрывает",
			rule:     hbaRule{Users: []string{"all"}, AuthMethod: "reject"},
			identity: "app_user", want: false,
		},
		{
			// Сломанная строка pg_hba сервером не применяется.
			name:     "строка с ошибкой не покрывает",
			rule:     hbaRule{Users: []string{"all"}, AuthMethod: "md5", Error: "invalid connection type"},
			identity: "app_user", want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleCoversUser(tc.rule, tc.identity, tc.memberOf); got != tc.want {
				t.Errorf("ruleCoversUser = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHBAUncovered(t *testing.T) {
	rules := []hbaRule{
		{Users: []string{"+app_read"}, AuthMethod: "scram-sha-256"},
		{Users: []string{"svc_bot"}, AuthMethod: "scram-sha-256"},
	}
	got := hbaUncovered(rules, map[string][]string{
		"svc_bot":  nil,
		"reader":   {"app_read"},
		"orphan":   nil,
		"orphan_2": {"app_write"},
	})
	want := []string{"orphan", "orphan_2"}
	if len(got) != len(want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uncovered = %v, want %v (sorted)", got, want)
		}
	}

	// Кластер с all-правилом предупреждений не даёт вовсе.
	if got := hbaUncovered([]hbaRule{{Users: []string{"all"}, AuthMethod: "md5"}},
		map[string][]string{"any": nil}); got != nil {
		t.Errorf("uncovered with an all rule = %v, want none", got)
	}

	// Пустой список правил не даёт выводов: делать их не из чего.
	if got := hbaUncovered(nil, map[string][]string{"any": nil}); got != nil {
		t.Errorf("uncovered without rules = %v, want none", got)
	}
}

func TestHBAIsCustomized(t *testing.T) {
	defaults := []hbaRule{
		{Number: 1, Type: "local", Databases: []string{"all"}, Users: []string{"postgres"}, AuthMethod: "peer"},
		{Number: 2, Type: "local", Databases: []string{"all"}, Users: []string{"all"}, AuthMethod: "peer"},
		{Number: 3, Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "scram-sha-256"},
		{Number: 4, Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "::1", Netmask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", AuthMethod: "scram-sha-256"},
		{Number: 5, Type: "local", Databases: []string{"replication"}, Users: []string{"all"}, AuthMethod: "peer"},
		{Number: 6, Type: "host", Databases: []string{"replication"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "scram-sha-256"},
	}
	if hbaIsCustomized(defaults) {
		t.Fatal("standard initdb rules are customized, want false")
	}
	if hbaIsCustomized(nil) {
		t.Fatal("empty rule set is customized, want false")
	}

	cases := map[string]hbaRule{
		"specific database": {Type: "host", Databases: []string{"appdb"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "scram-sha-256"},
		"specific user":     {Type: "host", Databases: []string{"all"}, Users: []string{"app"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "scram-sha-256"},
		"external network":  {Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "10.0.0.0", Netmask: "255.0.0.0", AuthMethod: "scram-sha-256"},
		"hostssl":           {Type: "hostssl", Databases: []string{"all"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "cert"},
		"reject":            {Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "reject"},
		"rule option":       {Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "127.0.0.1", Netmask: "255.255.255.255", AuthMethod: "cert", Options: []string{"clientcert=verify-full"}},
		"broken rule":       {Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Error: "invalid connection type"},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if !hbaIsCustomized([]hbaRule{rule}) {
				t.Fatalf("rule %+v is not customized, want true", rule)
			}
		})
	}
}

// Отсутствие ключа в Topology — штатная ситуация: движок не postgres,
// PostgreSQL младше 15 либо у admin-учётки нет прав на view.
func TestHBARulesFromTopology(t *testing.T) {
	rules, truncated, supported := hbaRulesFromTopology(json.RawMessage(
		`{"hba_rules":[{"number":1,"type":"host","users":["all"],"auth_method":"md5"}],"hba_rules_truncated":true}`))
	if !supported {
		t.Fatal("supported = false, want true")
	}
	if !truncated {
		t.Error("truncated = false, want true")
	}
	if len(rules) != 1 || rules[0].Number != 1 || rules[0].AuthMethod != "md5" {
		t.Errorf("rules = %+v, want a single md5 rule", rules)
	}

	for name, topology := range map[string]json.RawMessage{
		"пустая topology": nil,
		"нет ключа":       json.RawMessage(`{"in_recovery":false}`),
		"сломанный json":  json.RawMessage(`{`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, supported := hbaRulesFromTopology(topology); supported {
				t.Error("supported = true, want false")
			}
		})
	}
}
