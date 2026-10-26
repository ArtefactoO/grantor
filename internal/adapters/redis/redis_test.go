package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestManifest(t *testing.T) {
	m := New().Manifest()
	if m.Engine != Engine {
		t.Errorf("engine = %q, want %q", m.Engine, Engine)
	}
	if m.Version == "" || m.ConnectionSchema == "" {
		t.Error("manifest must set Version and ConnectionSchema")
	}
	for _, want := range []adapter.Capability{
		adapter.CapInventoryAccounts, adapter.CapInventoryPermissions,
		adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapAccountCreate, adapter.CapAccountDisable,
		adapter.CapAccountEnable, adapter.CapAccountDelete,
		adapter.CapCredentialProve,
		adapter.CapCredentialRotate,
	} {
		if !m.HasCapability(want) {
			t.Errorf("manifest must declare %q", want)
		}
	}
	// Ресурсов у Redis нет (см. doc-комментарий пакета): фиктивный
	// «инстанс»-ресурс сознательно не публикуется.
	if len(m.ResourceKinds) != 0 {
		t.Errorf("manifest must declare no resource kinds, got %v", m.ResourceKinds)
	}
	if m.HasCapability(adapter.CapInventoryResources) {
		t.Error("manifest must not declare inventory.resources")
	}
}

func TestProveCredentialRejectsIdentityMismatchBeforeDial(t *testing.T) {
	err := New().ProveCredential(t.Context(), adapter.Connection{},
		adapter.Account{EngineIdentity: "alice"},
		adapter.Credential{Username: "bob", Secret: []byte("not-a-secret")})
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("error = %v, want ErrExternalIdentityConflict", err)
	}
}

// Строки ниже — реальный вывод ACL LIST Redis 7.4 (см. doc-комментарии:
// сериализация канонична и совпадает с форматом aclfile).
const (
	lineDefault  = "user default on sanitize-payload #bc0811b1ac280523ae47131448a849eb1906736b975043c4fecef4ccfa626d15 ~* &* +@all"
	lineBare     = "user u1 on sanitize-payload #c592df4a86933b92addc9842402ddf198c638ea9be58916ee6e3734e1e3152f8 resetchannels -@all"
	lineRead     = "user u2 on sanitize-payload #072aa9e9 ~* &* -@all +@read -@dangerous"
	lineReadWr   = "user u3 on sanitize-payload #072aa9e9 ~* &* -@all +@read +@write -@dangerous"
	lineSelector = "user u4 on sanitize-payload #0c2e7ac3 resetchannels -@all (~app:* resetchannels -@all +get)"
	lineOff      = "user u5 off sanitize-payload #96e8866d resetchannels -@all +@read"
)

func TestParseACLListLine(t *testing.T) {
	t.Run("default admin", func(t *testing.T) {
		u, err := parseACLListLine(lineDefault)
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if u.name != "default" || !u.enabled || u.noPass || u.passwords != 1 {
			t.Errorf("user = %+v, want enabled default with one password", u)
		}
		if !slices.Equal(u.root.keys, []string{"~*"}) ||
			!slices.Equal(u.root.channels, []string{"&*"}) ||
			!slices.Equal(u.root.commands, []string{"+@all"}) {
			t.Errorf("root selector = %+v, want ~* &* +@all", u.root)
		}
		if len(u.unknown) != 0 || len(u.selectors) != 0 {
			t.Errorf("unexpected unknown/selectors: %+v", u)
		}
	})

	t.Run("bare user", func(t *testing.T) {
		u, err := parseACLListLine(lineBare)
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if len(u.root.keys) != 0 || len(u.root.channels) != 0 ||
			!slices.Equal(u.root.commands, []string{"-@all"}) {
			t.Errorf("root selector = %+v, want no keys/channels and -@all", u.root)
		}
	})

	t.Run("selector group", func(t *testing.T) {
		u, err := parseACLListLine(lineSelector)
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if len(u.selectors) != 1 {
			t.Fatalf("selectors = %+v, want one", u.selectors)
		}
		sel := u.selectors[0]
		if !slices.Equal(sel.keys, []string{"~app:*"}) ||
			!slices.Equal(sel.commands, []string{"-@all", "+get"}) {
			t.Errorf("selector = %+v, want ~app:* -@all +get", sel)
		}
	})

	t.Run("disabled user", func(t *testing.T) {
		u, err := parseACLListLine(lineOff)
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if u.enabled {
			t.Error("user u5 must be disabled (off)")
		}
	})

	t.Run("nopass and synonyms", func(t *testing.T) {
		u, err := parseACLListLine("user x on nopass allkeys allchannels allcommands")
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if !u.noPass {
			t.Error("nopass flag must be parsed")
		}
		if !slices.Equal(u.root.keys, []string{"~*"}) ||
			!slices.Equal(u.root.channels, []string{"&*"}) ||
			!slices.Equal(u.root.commands, []string{"+@all"}) {
			t.Errorf("synonyms must normalize to ~* &* +@all, got %+v", u.root)
		}
	})

	t.Run("unknown token is preserved", func(t *testing.T) {
		u, err := parseACLListLine("user x on bogus-token -@all")
		if err != nil {
			t.Fatalf("parseACLListLine: %v", err)
		}
		if !slices.Equal(u.unknown, []string{"bogus-token"}) {
			t.Errorf("unknown = %v, want [bogus-token]", u.unknown)
		}
	})

	t.Run("errors", func(t *testing.T) {
		if _, err := parseACLListLine("not-a-user-line"); err == nil {
			t.Error("malformed line must fail")
		}
		if _, err := parseACLListLine("user x on (~a"); err == nil {
			t.Error("unbalanced selector parenthesis must fail")
		}
		// Текст ошибки не должен цитировать всю строку (в ней хэши паролей).
		_, err := parseACLListLine("bogus #deadbeef-password-hash")
		if err == nil {
			t.Fatal("malformed line must fail")
		}
		if strings.Contains(err.Error(), "deadbeef") {
			t.Errorf("parse error leaks line contents: %v", err)
		}
	})
}

// TestMatchBundlesBothDirections проверяет соответствие канонических
// сериализаций managed-форм наборам bundles (наблюдение) и обратное
// построение правил rulesFor (мутации).
func TestMatchBundlesBothDirections(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		bundles []string
	}{
		{"empty", lineBare, nil},
		{"read", lineRead, []string{bundleRead}},
		{"read+write", lineReadWr, []string{bundleRead, bundleWrite}},
		{"write", "user w on #h ~* &* -@all +@write -@dangerous", []string{bundleWrite}},
		{"admin", "user a on #h ~* &* +@all", []string{bundleAdmin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseACLListLine(tc.line)
			if err != nil {
				t.Fatalf("parseACLListLine: %v", err)
			}
			bundles, managed := matchBundles(u)
			if !managed {
				t.Fatalf("user %q must be managed", u.name)
			}
			if !slices.Equal(sortedClone(bundles), sortedClone(tc.bundles)) {
				t.Errorf("bundles = %v, want %v", bundles, tc.bundles)
			}
		})
	}

	unmanaged := []struct {
		name string
		line string
	}{
		{"no dangerous carve-out", "user x on #h ~* &* -@all +@read"},
		{"scoped keys", "user x on #h ~app:* &* -@all +@read -@dangerous"},
		{"no channels", "user x on #h ~* -@all +@read -@dangerous"},
		{"extra command", "user x on #h ~* &* -@all +@read -@dangerous +get"},
		{"selector present", lineSelector},
		{"unknown token", "user x on bogus -@all"},
	}
	for _, tc := range unmanaged {
		t.Run("unmanaged "+tc.name, func(t *testing.T) {
			u, err := parseACLListLine(tc.line)
			if err != nil {
				t.Fatalf("parseACLListLine: %v", err)
			}
			if _, managed := matchBundles(u); managed {
				t.Errorf("user from %q must be unmanaged", tc.line)
			}
		})
	}
}

func TestRulesFor(t *testing.T) {
	base := []string{"nocommands", "resetkeys", "resetchannels"}
	tests := []struct {
		bundles []string
		want    []string
	}{
		{nil, base},
		{[]string{bundleRead}, append(slices.Clone(base), "~*", "&*", "+@read", "-@dangerous")},
		{[]string{bundleWrite}, append(slices.Clone(base), "~*", "&*", "+@write", "-@dangerous")},
		{[]string{bundleWrite, bundleRead}, append(slices.Clone(base), "~*", "&*", "+@read", "+@write", "-@dangerous")},
		{[]string{bundleAdmin}, append(slices.Clone(base), "~*", "&*", "+@all")},
	}
	for _, tt := range tests {
		got, err := rulesFor(tt.bundles)
		if err != nil {
			t.Errorf("rulesFor(%v): %v", tt.bundles, err)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("rulesFor(%v) = %v, want %v", tt.bundles, got, tt.want)
		}
	}
}

// TestRulesForRejectsAdminCombination фиксирует запрет непредставимых наборов:
// +@all стирает read/write в движке, поэтому такой набор нельзя сериализовать
// молча — иначе последующий revoke снесёт «поглощённые» права.
func TestRulesForRejectsAdminCombination(t *testing.T) {
	for _, bundles := range [][]string{
		{bundleRead, bundleAdmin},
		{bundleWrite, bundleAdmin},
		{bundleRead, bundleWrite, bundleAdmin},
	} {
		got, err := rulesFor(bundles)
		if err == nil {
			t.Errorf("rulesFor(%v) = %v, want ErrBundleCombination", bundles, got)
			continue
		}
		if !errors.Is(err, ErrBundleCombination) {
			t.Errorf("rulesFor(%v) error = %v, want ErrBundleCombination", bundles, err)
		}
		if !strings.Contains(err.Error(), bundleAdmin) {
			t.Errorf("error %q must name the admin bundle", err)
		}
	}
}

// TestNormalizeBundles проверяет канонический порядок и дедупликацию: от них
// зависит сравнение наблюдаемого и целевого наборов.
func TestNormalizeBundles(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{nil, []string{}},
		{[]string{bundleWrite, bundleRead}, []string{bundleRead, bundleWrite}},
		{[]string{bundleRead, bundleRead}, []string{bundleRead}},
		{[]string{bundleAdmin, bundleRead}, []string{bundleRead, bundleAdmin}},
		{[]string{"acl:~* &* -@all"}, []string{}},
	}
	for _, tt := range tests {
		if got := normalizeBundles(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("normalizeBundles(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestEvalCommandOrderAware(t *testing.T) {
	sel := func(rules ...string) aclSelector { return aclSelector{commands: rules} }
	flushCats := dangerousProbeCommands["flushall"]

	if !evalCommand(sel("+@all"), "flushall", flushCats).full {
		t.Error("+@all must allow flushall")
	}
	if !evalCommand(sel("-@all", "+@write"), "flushall", flushCats).full {
		t.Error("+@write must allow flushall (FLUSHALL is in @write)")
	}
	if evalCommand(sel("-@all", "+@write", "-@dangerous"), "flushall", flushCats).full {
		t.Error("+@write -@dangerous must not allow flushall (order matters)")
	}
	if !evalCommand(sel("-@dangerous", "+@write"), "flushall", flushCats).full {
		t.Error("-@dangerous before +@write must allow flushall (order matters)")
	}
	if !evalCommand(sel("-@all", "+flushall"), "flushall", flushCats).full {
		t.Error("explicit +flushall must allow flushall")
	}
	if evalCommand(sel("+@all", "-flushall"), "flushall", flushCats).full {
		t.Error("explicit -flushall must deny flushall")
	}

	aclCats := dangerousProbeCommands["acl"]
	perm := evalCommand(sel("-@all", "+acl|whoami", "+acl|list"), "acl", aclCats)
	if perm.full {
		t.Error("subcommand grants must not allow the full acl command")
	}
	if !perm.subs["whoami"] || !perm.subs["list"] || perm.subs["setuser"] {
		t.Errorf("subs = %v, want whoami+list only", perm.subs)
	}
	perm = evalCommand(sel("-@all", "+acl|whoami", "-acl|whoami"), "acl", aclCats)
	if perm.subs["whoami"] {
		t.Error("-acl|whoami must remove the subcommand grant")
	}
}

func TestDangerousClassification(t *testing.T) {
	user := func(rules ...string) aclUser {
		return aclUser{root: aclSelector{commands: rules}}
	}
	dangerous := [][]string{
		{"+@all"},
		{"-@all", "+@admin"},
		// +@slow действительно даёт команду acl (проверено на живом Redis).
		{"-@all", "+@slow"},
		{"-@all", "+@dangerous"},
		{"-@all", "+@write"}, // FLUSHALL входит в @write
		{"-@all", "+acl"},
		{"-@all", "+config"},
		{"-@all", "+shutdown"},
		{"-@all", "+flushall"},
	}
	for _, rules := range dangerous {
		if !userDangerous(user(rules...)) {
			t.Errorf("rules %v must be dangerous", rules)
		}
	}
	safe := [][]string{
		{"-@all"},
		{"-@all", "+@read", "-@dangerous"},
		{"-@all", "+@write", "-@dangerous"},
		{"-@all", "+@read"}, // KEYS опасна, но класс ACL/CONFIG/FLUSH/SHUTDOWN не разрешён
		{"-@all", "+get", "+set"},
		{"-@all", "+acl|whoami"}, // частичный acl не даёт администрирования
	}
	for _, rules := range safe {
		if userDangerous(user(rules...)) {
			t.Errorf("rules %v must not be dangerous", rules)
		}
	}

	// Опасный селектор делает опасным всего пользователя.
	u := user("-@all")
	u.selectors = []aclSelector{{commands: []string{"-@all", "+@admin"}}}
	if !userDangerous(u) {
		t.Error("dangerous selector must make the user dangerous")
	}
}

func TestAclAdminAllowed(t *testing.T) {
	user := func(rules ...string) aclUser {
		return aclUser{root: aclSelector{commands: rules}}
	}
	allowed := [][]string{
		{"+@all"},
		{"-@all", "+@admin"},
		{"-@all", "+@slow"},
		{"-@all", "+acl"},
		{"-@all", "+acl|whoami", "+acl|list", "+acl|getuser", "+acl|setuser", "+acl|deluser", "+acl|save"},
	}
	for _, rules := range allowed {
		if !aclAdminAllowed(user(rules...)) {
			t.Errorf("rules %v must allow ACL administration", rules)
		}
	}
	denied := [][]string{
		{"-@all"},
		{"-@all", "+@read"},
		{"-@all", "+acl|whoami", "+acl|list"},
		{"-@all", "+acl|whoami", "+acl|list", "+acl|getuser", "+acl|setuser", "+acl|deluser"},
		{"+@all", "-acl"},
		{"+@all", "-@admin", "-@slow", "-@dangerous"},
	}
	for _, rules := range denied {
		if aclAdminAllowed(user(rules...)) {
			t.Errorf("rules %v must not allow ACL administration", rules)
		}
	}

	// Селектор с полным acl тоже даёт администрирование.
	u := user("-@all")
	u.selectors = []aclSelector{{commands: []string{"-@all", "+acl"}}}
	if !aclAdminAllowed(u) {
		t.Error("selector granting +acl must allow ACL administration")
	}
}

func TestTopologyFromInfo(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		info := parseInfo("# Server\r\nredis_version:7.4.9\r\nredis_mode:standalone\r\n" +
			"# Replication\r\nrole:master\r\nconnected_slaves:0\r\n")
		topo := topologyFromInfo(info)
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
		if topo["role"] != "master" {
			t.Errorf("role = %v, want master", topo["role"])
		}
		if _, ok := topo["connected_replicas"]; ok {
			t.Error("connected_replicas must be omitted for 0")
		}
		if info["redis_version"] != "7.4.9" {
			t.Errorf("redis_version = %q, want 7.4.9", info["redis_version"])
		}
	})

	t.Run("cluster", func(t *testing.T) {
		info := parseInfo("redis_version:7.4.9\r\nredis_mode:cluster\r\nrole:master\r\nconnected_slaves:2\r\n")
		topo := topologyFromInfo(info)
		if topo["topology"] != "cluster" {
			t.Errorf("topology = %v, want cluster", topo["topology"])
		}
		if topo["connected_replicas"] != "2" {
			t.Errorf("connected_replicas = %v, want 2", topo["connected_replicas"])
		}
		addClusterInfo(topo, parseInfo("cluster_state:ok\r\ncluster_size:3\r\ncluster_known_nodes:6\r\n"))
		if topo["cluster_state"] != "ok" || topo["cluster_size"] != "3" || topo["cluster_known_nodes"] != "6" {
			t.Errorf("cluster info not merged: %v", topo)
		}
	})

	t.Run("sentinel", func(t *testing.T) {
		topo := topologyFromInfo(parseInfo("redis_mode:sentinel\r\n"))
		if topo["topology"] != "sentinel" {
			t.Errorf("topology = %v, want sentinel", topo["topology"])
		}
	})

	t.Run("missing mode defaults to standalone", func(t *testing.T) {
		topo := topologyFromInfo(map[string]string{})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
	})
}

func TestBundlePermissions(t *testing.T) {
	perms := bundlePermissions()
	byID := map[string]adapter.ObservedPermission{}
	for _, p := range perms {
		byID[p.ExternalID] = p
		if !p.Assignable {
			t.Errorf("bundle %q must be assignable", p.ExternalID)
		}
		if p.ScopeExternalID != "" {
			t.Errorf("bundle %q scope = %q, want cluster-wide (empty)", p.ExternalID, p.ScopeExternalID)
		}
	}
	if p := byID[bundleAdmin]; !p.Dangerous {
		t.Error("admin bundle must be dangerous")
	}
	for _, name := range []string{bundleRead, bundleWrite} {
		if byID[name].Dangerous {
			t.Errorf("%s bundle must not be dangerous", name)
		}
	}
}

func TestRawACLPermissionSignature(t *testing.T) {
	u, err := parseACLListLine(lineSelector)
	if err != nil {
		t.Fatalf("parseACLListLine: %v", err)
	}
	p := rawACLPermission(u)
	if p.Assignable {
		t.Error("raw acl permission must not be assignable")
	}
	if !strings.HasPrefix(p.ExternalID, rawPermissionPrefix) {
		t.Errorf("external id = %q, want %q prefix", p.ExternalID, rawPermissionPrefix)
	}
	// Хэш пароля из строки ACL LIST не должен попадать в сигнатуру.
	if strings.Contains(p.ExternalID, "0c2e7ac3") {
		t.Errorf("permission id leaks password hash: %q", p.ExternalID)
	}
	if !strings.Contains(p.ExternalID, "(~app:* -@all +get)") {
		t.Errorf("permission id must describe the selector, got %q", p.ExternalID)
	}

	// Одинаковые правила у разных пользователей дают один external id.
	u2 := u
	u2.name = "other"
	if rawACLPermission(u2).ExternalID != p.ExternalID {
		t.Error("identical rules must produce identical permission ids")
	}

	admin, err := parseACLListLine("user root on #h ~* &* +@all +@admin")
	if err != nil {
		t.Fatalf("parseACLListLine: %v", err)
	}
	if got := rawACLPermission(admin); !got.Dangerous {
		t.Error("raw permission with admin rules must be dangerous")
	}
	safe, err := parseACLListLine("user ro on #h ~cache:* -@all +get")
	if err != nil {
		t.Fatalf("parseACLListLine: %v", err)
	}
	if got := rawACLPermission(safe); got.Dangerous {
		t.Error("raw permission with a scoped +get must not be dangerous")
	}
}

func TestParseBundle(t *testing.T) {
	for _, ok := range []string{bundleRead, bundleWrite, bundleAdmin} {
		if _, err := parseBundle(ok); err != nil {
			t.Errorf("parseBundle(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "acl:~* &* +@all", "read-only", "cluster-admin"} {
		if _, err := parseBundle(bad); err == nil {
			t.Errorf("parseBundle(%q): expected error", bad)
		}
	}
}

func TestPlanAccessRedactsSecretAndParses(t *testing.T) {
	ad := New()
	const marker = "s3cr3t-marker"
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission: bundleRead,
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	}
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepGrantPermission {
		t.Fatalf("unexpected plan steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	for k, v := range step.Attributes {
		if strings.Contains(fmt.Sprint(v), marker) {
			t.Errorf("plan attribute %q leaks secret", k)
		}
	}
	if step.Attributes["user"] != "svc" || step.Attributes["bundle"] != bundleRead {
		t.Errorf("plan attributes = %v, want user=svc bundle=read", step.Attributes)
	}

	revoke := change
	revoke.Kind = adapter.ChangeRevoke
	rplan, err := ad.Plan(t.Context(), revoke)
	if err != nil {
		t.Fatalf("Plan(revoke): %v", err)
	}
	if rplan.Steps[0].Kind != stepRevokePermission {
		t.Errorf("revoke step kind = %q, want %q", rplan.Steps[0].Kind, stepRevokePermission)
	}

	// Observed acl-permissions не назначаемы.
	raw := change
	raw.Permission = "acl:~* &* +@all"
	if _, err := ad.Plan(t.Context(), raw); err == nil {
		t.Error("Plan(grant) with an observed acl permission must fail")
	}
}

// TestPlanAccessDesiredState фиксирует работу с desired-состоянием ядра:
// целевой набор попадает в план, непредставимый набор отклоняется внятной
// ошибкой, а набор, противоречащий самому изменению, — ошибка контракта.
func TestPlanAccessDesiredState(t *testing.T) {
	ad := New()
	account := adapter.Account{Kind: "login", EngineIdentity: "svc"}
	change := func(kind adapter.ChangeKind, permission string, desired []string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: kind, Account: account, Permission: permission, AccountPermissions: desired,
		}
	}

	t.Run("target bundles are planned", func(t *testing.T) {
		plan, err := ad.Plan(t.Context(),
			change(adapter.ChangeRevoke, bundleAdmin, []string{bundleRead}))
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		step := plan.Steps[0]
		if step.Attributes["target_bundles"] != bundleRead {
			t.Errorf("target_bundles = %v, want %q", step.Attributes["target_bundles"], bundleRead)
		}
		if !strings.Contains(step.Description, "remaining bundles: read") {
			t.Errorf("description = %q, want it to name the remaining bundles", step.Description)
		}
	})

	t.Run("empty desired set is not nil", func(t *testing.T) {
		plan, err := ad.Plan(t.Context(),
			change(adapter.ChangeRevoke, bundleRead, []string{}))
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if !strings.Contains(plan.Steps[0].Description, "no bundles remain") {
			t.Errorf("description = %q, want it to state that nothing remains",
				plan.Steps[0].Description)
		}
	})

	t.Run("admin combined with read is rejected", func(t *testing.T) {
		_, err := ad.Plan(t.Context(),
			change(adapter.ChangeGrant, bundleAdmin, []string{bundleRead, bundleAdmin}))
		if !errors.Is(err, ErrBundleCombination) {
			t.Fatalf("Plan error = %v, want ErrBundleCombination", err)
		}
		if !strings.Contains(err.Error(), bundleRead) {
			t.Errorf("error %q must name the bundle that admin would erase", err)
		}
	})

	t.Run("desired set must agree with the change", func(t *testing.T) {
		if _, err := ad.Plan(t.Context(),
			change(adapter.ChangeRevoke, bundleRead, []string{bundleRead})); err == nil {
			t.Error("revoke whose desired set still contains the bundle must fail")
		}
		if _, err := ad.Plan(t.Context(),
			change(adapter.ChangeGrant, bundleRead, []string{bundleWrite})); err == nil {
			t.Error("grant whose desired set lacks the bundle must fail")
		}
	})

	t.Run("unassignable permissions are ignored", func(t *testing.T) {
		plan, err := ad.Plan(t.Context(),
			change(adapter.ChangeGrant, bundleRead, []string{bundleRead, "acl:~app:* +get"}))
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if plan.Steps[0].Attributes["target_bundles"] != bundleRead {
			t.Errorf("target_bundles = %v, want %q",
				plan.Steps[0].Attributes["target_bundles"], bundleRead)
		}
	})
}

func TestPlanAccountCreateRequiresPassword(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountCreate,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("account.create without password credential must fail")
	}

	// Форма плана проверяется без target: сам Plan обращается к Redis, чтобы
	// отказать в создании поверх существующего пользователя.
	const marker = "s3cr3t-marker"
	plan := accountCreatePlan(adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	})
	step := plan.Steps[0]
	if step.Kind != stepCreateUser || step.Attributes["with_password"] != true {
		t.Errorf("unexpected create step: %+v", step)
	}
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
}

func TestPlanDisableEnable(t *testing.T) {
	ad := New()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}

	dis, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(disable): %v", err)
	}
	if dis.Steps[0].Kind != stepDisableUser || dis.Steps[0].Attributes["flag"] != "off" {
		t.Errorf("disable step = %+v, want kind %q flag off", dis.Steps[0], stepDisableUser)
	}

	en, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(enable): %v", err)
	}
	if en.Steps[0].Kind != stepEnableUser || en.Steps[0].Attributes["flag"] != "on" {
		t.Errorf("enable step = %+v, want kind %q flag on", en.Steps[0], stepEnableUser)
	}
}

func TestPlanRefusesDefaultUser(t *testing.T) {
	ad := New()
	def := adapter.Account{Kind: "login", EngineIdentity: defaultUserName}
	kinds := []adapter.ChangeKind{
		adapter.ChangeGrant, adapter.ChangeRevoke, adapter.ChangeAccountCreate,
		adapter.ChangeAccountDisable, adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
	}
	for _, kind := range kinds {
		_, err := ad.Plan(t.Context(), adapter.DesiredChange{
			Kind:       kind,
			Account:    def,
			Permission: bundleRead,
			Credential: &adapter.Credential{Kind: "password", Secret: []byte("pw")},
		})
		if err == nil {
			t.Errorf("Plan(%s) for the default user must fail", kind)
		}
	}
	if err := New().RotateCredential(t.Context(), adapter.Connection{}, def,
		adapter.Credential{Kind: "password", Secret: []byte("pw")}); err == nil {
		t.Error("RotateCredential for the default user must fail")
	}
}

func TestPlanUnsupportedChange(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeResourceCreate,
		Account: adapter.Account{EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("Plan(resource.create): expected unsupported change error")
	}
}

func TestGenerateCredential(t *testing.T) {
	ad := New()
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if cred.Kind != "password" {
		t.Errorf("kind = %q, want password", cred.Kind)
	}
	if len(cred.Secret) != adapterutil.DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(cred.Secret), adapterutil.DefaultPasswordLength)
	}
	for _, b := range cred.Secret {
		if !strings.ContainsRune(adapterutil.PasswordAlphabet, rune(b)) {
			t.Fatalf("password contains char outside alphabet: %q", string(b))
		}
	}

	custom, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{Length: 12})
	if err != nil {
		t.Fatalf("GenerateCredential(12): %v", err)
	}
	if len(custom.Secret) != 12 {
		t.Errorf("custom length = %d, want 12", len(custom.Secret))
	}

	other, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated passwords must differ")
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "redis.example.com:6380", host: "redis.example.com", port: 6380},
		{endpoint: "redis.example.com", host: "redis.example.com", port: defaultPort},
		{endpoint: "[::1]:6379", host: "::1", port: 6379},
		{endpoint: "redis.example.com:notaport", wantErr: true},
		{endpoint: "redis.example.com:0", wantErr: true},
		{endpoint: "", wantErr: true},
	}
	for _, tt := range tests {
		host, port, err := adapterutil.SplitEndpoint(tt.endpoint, defaultPort)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitEndpoint(%q): expected error", tt.endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitEndpoint(%q): %v", tt.endpoint, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("splitEndpoint(%q) = (%q, %d), want (%q, %d)", tt.endpoint, host, port, tt.host, tt.port)
		}
	}
}

func TestNewClientNoSecretLeak(t *testing.T) {
	const password = "s3cr3t-admin-password"
	cfg := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"redis.example.com:6379"},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte(password),
		},
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	defer c.close()
	if c.username != "admin" {
		t.Errorf("username = %q, want admin", c.username)
	}

	// Секрет не должен появляться ни в одном текстовом представлении
	// клиентской обёртки.
	for _, rendered := range []string{
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprintf("%s", c.secret),
		fmt.Sprintf("%v", c.secret),
	} {
		if strings.Contains(rendered, password) {
			t.Errorf("rendered client leaks secret: %q", rendered)
		}
	}
	raw, err := json.Marshal(c.secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	if strings.Contains(string(raw), password) {
		t.Errorf("marshaled secret leaks value: %s", raw)
	}
}

func TestNewClientValidation(t *testing.T) {
	base := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"redis.example.com:6379"},
		AdminCredential: adapter.Credential{
			Kind: "password", Username: "admin", Secret: []byte("pw"),
		},
	}

	noEndpoints := base
	noEndpoints.Endpoints = nil
	if _, err := newClient(noEndpoints); err == nil {
		t.Error("newClient without endpoints must fail")
	}

	noSecret := base
	noSecret.AdminCredential.Secret = nil
	if _, err := newClient(noSecret); err == nil {
		t.Error("newClient without admin secret must fail")
	}

	// Пустой username допустим: AUTH идёт от имени default (requirepass).
	noUser := base
	noUser.AdminCredential.Username = ""
	c, err := newClient(noUser)
	if err != nil {
		t.Errorf("newClient with empty username (default user) must work: %v", err)
	} else {
		c.close()
	}

	badTLS := base
	badTLS.TLS = adapter.TLSConfig{Mode: "bogus"}
	if _, err := newClient(badTLS); err == nil {
		t.Error("newClient with unsupported tls mode must fail")
	}
}

// fakeRedisErr реализует goredis.Error (ответ сервера) для тестов редактора.
type fakeRedisErr string

func (e fakeRedisErr) Error() string { return string(e) }
func (e fakeRedisErr) RedisError()   {}

func TestRedactACLError(t *testing.T) {
	const password = "s3cr3t-created-password"

	// Ответ сервера цитирует аргумент команды (реальный формат Redis:
	// "ERR Error in ACL SETUSER modifier '<arg>': ...") — от него остаётся
	// только класс ошибки.
	srvErr := fakeRedisErr("ERR Error in ACL SETUSER modifier '>" + password + "': Syntax error")
	got := redactACLError(srvErr, password)
	if strings.Contains(got.Error(), password) {
		t.Errorf("redacted server error leaks password: %q", got.Error())
	}
	if !strings.Contains(got.Error(), "ERR") {
		t.Errorf("redacted server error = %q, want it to keep the ERR class", got.Error())
	}

	// NOPERM-класс сохраняется — по нему можно понять причину без секрета.
	nopermErr := fakeRedisErr("NOPERM this user has no permissions to run the 'acl|setuser' command")
	if got := redactACLError(nopermErr, password); !strings.Contains(got.Error(), "NOPERM") {
		t.Errorf("redacted error = %q, want NOPERM class", got.Error())
	}

	// Не-серверная ошибка (сеть): секрет вычищается, остальное сохраняется.
	netErr := fmt.Errorf("write tcp: broken pipe after sending >%s", password)
	got = redactACLError(netErr, password)
	if strings.Contains(got.Error(), password) {
		t.Errorf("redacted network error leaks password: %q", got.Error())
	}
	if !strings.Contains(got.Error(), "broken pipe") {
		t.Errorf("redacted network error = %q, want original context kept", got.Error())
	}
}
