package redis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Имена permission bundles (external ids). Observed acl-permissions живут в
// пространстве имён "acl:" и с bundles не пересекаются.
const (
	bundleRead       = "read"
	bundleWrite      = "write"
	bundleMonitoring = "monitoring"
	bundleAdmin      = "admin"

	rawPermissionPrefix = "acl:"
)

// Канонические правила bundles (см. doc-комментарий пакета). Порядок токенов
// совпадает с канонической сериализацией ACL LIST, проверенной на живом
// Redis 7.
var bundleRules = map[string][]string{
	bundleRead:       {"~*", "&*", "+@read", "-@dangerous"},
	bundleWrite:      {"~*", "&*", "+@write", "-@dangerous"},
	bundleMonitoring: {"+ping", "+info", "+hello", "+client|setname", "+client|setinfo"},
	bundleAdmin:      {"~*", "&*", "+@all"},
}

// aclSelector — набор правил одного селектора ACL-пользователя: root-правила
// или дополнительный селектор "(...)".
type aclSelector struct {
	// keys — паттерны ключей: "~*", "%R~cache:*".
	keys []string
	// channels — паттерны Pub/Sub-каналов: "&*", "&events".
	channels []string
	// commands — правила команд в порядке применения: "-@all", "+@read",
	// "+get", "+acl|whoami".
	commands []string
}

// aclUser — разобранная строка ACL LIST одного пользователя. Хэши паролей не
// сохраняются (только их число): им не место в snapshot и attributes.
type aclUser struct {
	name      string
	enabled   bool
	noPass    bool
	passwords int
	root      aclSelector
	selectors []aclSelector
	// unknown — нераспознанные токены; их наличие делает пользователя
	// unmanaged, чтобы неизвестные правила не потерялись молча.
	unknown []string
}

// aclListUsers читает и разбирает ACL LIST. Ошибка запроса возвращается как
// есть (по NOPERM ValidateConnection распознаёт нехватку привилегий).
func (c *adminClient) aclListUsers(ctx context.Context) ([]aclUser, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	lines, err := c.rdb.ACLList(reqCtx).Result()
	if err != nil {
		return nil, err
	}
	users := make([]aclUser, 0, len(lines))
	for _, line := range lines {
		u, err := parseACLListLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse acl list entry: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}

// findUser возвращает пользователя по имени.
func findUser(users []aclUser, name string) (aclUser, bool) {
	for _, u := range users {
		if u.name == name {
			return u, true
		}
	}
	return aclUser{}, false
}

// parseACLListLine разбирает одну строку ACL LIST — каноническую сериализацию
// ACL-пользователя ("user <name> <rule>..."). Формат общий с aclfile и
// содержимым ACL GETUSER; селекторы приходят скобочными группами.
func parseACLListLine(line string) (aclUser, error) {
	tokens, err := tokenizeACLLine(line)
	if err != nil {
		return aclUser{}, err
	}
	if len(tokens) < 2 || tokens[0] != "user" {
		return aclUser{}, fmt.Errorf("unexpected acl list line format %q", firstToken(line))
	}
	u := aclUser{name: tokens[1]}
	for _, tok := range tokens[2:] {
		if strings.HasPrefix(tok, "(") && strings.HasSuffix(tok, ")") {
			inner := strings.Fields(tok[1 : len(tok)-1])
			sel := aclSelector{}
			var selUnknown []string
			classifySelectorTokens(inner, &sel, &selUnknown)
			u.selectors = append(u.selectors, sel)
			u.unknown = append(u.unknown, selUnknown...)
			continue
		}
		classifyUserToken(tok, &u)
	}
	return u, nil
}

// classifyUserToken классифицирует один токен уровня пользователя.
func classifyUserToken(tok string, u *aclUser) {
	switch tok {
	case "on":
		u.enabled = true
	case "off":
		u.enabled = false
	case "nopass":
		u.noPass = true
	case "sanitize-payload", "skip-sanitize-payload", "clearselectors":
		// Нейтральные флаги: на модель прав не влияют.
	default:
		if strings.HasPrefix(tok, "#") {
			u.passwords++
			return
		}
		classifySelectorTokens([]string{tok}, &u.root, &u.unknown)
	}
}

// classifySelectorTokens раскладывает токены правил по полям селектора.
// Синонимы allkeys/allchannels/allcommands/nocommands нормализуются к
// каноническим "~*", "&*", "+@all", "-@all".
func classifySelectorTokens(tokens []string, sel *aclSelector, unknown *[]string) {
	for _, tok := range tokens {
		switch {
		case tok == "allkeys":
			sel.keys = append(sel.keys, "~*")
		case tok == "allchannels":
			sel.channels = append(sel.channels, "&*")
		case tok == "allcommands":
			sel.commands = append(sel.commands, "+@all")
		case tok == "nocommands":
			sel.commands = append(sel.commands, "-@all")
		case tok == "resetkeys":
			sel.keys = nil
		case tok == "resetchannels":
			sel.channels = nil
		case tok == "sanitize-payload", tok == "skip-sanitize-payload":
			// Нейтральные флаги встречаются и внутри селекторов.
		case strings.HasPrefix(tok, "~"), strings.HasPrefix(tok, "%"):
			sel.keys = append(sel.keys, tok)
		case strings.HasPrefix(tok, "&"):
			sel.channels = append(sel.channels, tok)
		case strings.HasPrefix(tok, "+"), strings.HasPrefix(tok, "-"):
			sel.commands = append(sel.commands, strings.ToLower(tok))
		default:
			*unknown = append(*unknown, tok)
		}
	}
}

// tokenizeACLLine разбивает строку на токены, собирая скобочные группы
// селекторов (внутри них есть пробелы) в единые токены.
func tokenizeACLLine(line string) ([]string, error) {
	fields := strings.Fields(line)
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !strings.HasPrefix(f, "(") {
			out = append(out, f)
			continue
		}
		group := []string{f}
		for !strings.HasSuffix(group[len(group)-1], ")") {
			i++
			if i >= len(fields) {
				return nil, fmt.Errorf("unbalanced selector parenthesis near %q", firstToken(f))
			}
			group = append(group, fields[i])
		}
		out = append(out, strings.Join(group, " "))
	}
	return out, nil
}

// firstToken возвращает первый токен строки для безопасных сообщений об
// ошибках (не цитировать всю строку: она может содержать хэши паролей).
func firstToken(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

// --- Managed-формы и bundle matching ---

// matchBundles сопоставляет полный набор правил пользователя одной из
// managed-форм. Возвращает набор bundles и признак managed. Managed-формы:
// пустая (нет прав), любое непустое подмножество {read, write, monitoring}
// и {admin}. Monitoring alone has no key/channel access.
// Формы взаимно однозначны с наборами bundles: admin не комбинируется с
// read/write/monitoring (см. checkBundleSet), поэтому по ACL всегда восстановим ровно
// тот набор, который был выдан. Селекторы, нераспознанные токены и любые
// другие правила — unmanaged.
func matchBundles(u aclUser) ([]string, bool) {
	if len(u.unknown) > 0 || len(u.selectors) > 0 {
		return nil, false
	}
	cmds := sortedClone(u.root.commands)
	keys := sortedClone(u.root.keys)
	channels := sortedClone(u.root.channels)

	if len(keys) == 0 && len(channels) == 0 &&
		(len(cmds) == 0 || slices.Equal(cmds, []string{"-@all"})) {
		return nil, true
	}
	if slices.Equal(keys, []string{"~*"}) && slices.Equal(channels, []string{"&*"}) &&
		slices.Equal(cmds, []string{"+@all"}) {
		return []string{bundleAdmin}, true
	}
	// Match only exact canonical forms. Monitoring alone grants neither key
	// nor channel access; combining it with read/write must preserve both
	// separately observable bundles so a later revoke cannot erase the other.
	ordinary := []string{bundleRead, bundleWrite, bundleMonitoring}
	for mask := 1; mask < 1<<len(ordinary); mask++ {
		var bundles []string
		for i, name := range ordinary {
			if mask&(1<<i) != 0 {
				bundles = append(bundles, name)
			}
		}
		rules, err := rulesFor(bundles)
		if err != nil {
			return nil, false
		}
		var expected aclSelector
		var unknown []string
		classifySelectorTokens(rules, &expected, &unknown)
		if len(unknown) == 0 && slices.Equal(keys, sortedClone(expected.keys)) &&
			slices.Equal(channels, sortedClone(expected.channels)) &&
			slices.Equal(cmds, sortedClone(expected.commands)) {
			return bundles, true
		}
	}
	return nil, false
}

// ErrBundleCombination сообщает, что набор bundles не представим в ACL Redis
// без потери информации (см. checkBundleSet).
var ErrBundleCombination = errors.New("redis bundle combination is not representable")

// normalizeBundles возвращает набор bundles в каноническом порядке
// (read, write, monitoring, admin) без дубликатов. Порядок фиксирован, чтобы сравнение
// наборов и сообщения об ошибках были детерминированы.
func normalizeBundles(bundles []string) []string {
	out := make([]string, 0, len(bundleRules))
	for _, name := range []string{bundleRead, bundleWrite, bundleMonitoring, bundleAdmin} {
		if slices.Contains(bundles, name) {
			out = append(out, name)
		}
	}
	return out
}

// checkBundleSet проверяет, что набор bundles представим в ACL Redis без
// потери информации.
//
// Bundle admin — это правило +@all, а +@all в Redis канонизирует описание
// правил пользователя до единственного токена: read и write, выданные вместе
// с admin, перестают существовать в движке физически, а не только визуально.
// Восстановить из такого ACL исходный набор невозможно, поэтому сочетание
// admin с read/write запрещено явно и с внятной ошибкой — вместо тихой потери
// прав при последующем revoke. Семантически запрет ничего не отнимает: admin
// (+@all) — строгое надмножество read и write.
func checkBundleSet(bundles []string) error {
	if !slices.Contains(bundles, bundleAdmin) {
		return nil
	}
	var subsumed []string
	for _, name := range []string{bundleRead, bundleWrite, bundleMonitoring} {
		if slices.Contains(bundles, name) {
			subsumed = append(subsumed, strconv.Quote(name))
		}
	}
	if len(subsumed) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w: bundle %q (+@all) already includes %s and erases them in the engine ACL; "+
			"revoke %s first or keep them instead of %q",
		ErrBundleCombination, bundleAdmin, strings.Join(subsumed, ", "),
		strings.Join(subsumed, ", "), bundleAdmin)
}

// rulesFor строит аргументы ACL SETUSER, приводящие права пользователя к
// целевому набору bundles. Правила перечисляются после полного сброса
// (nocommands resetkeys resetchannels), поэтому итоговая сериализация
// детерминирована и не зависит от истории; пароли и флаг on/off не
// затрагиваются. SETUSER применяет весь список атомарно.
//
// Непредставимый набор (см. checkBundleSet) — ошибка: молча сериализовать
// admin+read в +@all значит потерять read.
func rulesFor(bundles []string) ([]string, error) {
	if err := checkBundleSet(bundles); err != nil {
		return nil, err
	}
	rules := []string{"nocommands", "resetkeys", "resetchannels"}
	if len(bundles) == 0 {
		return rules, nil
	}
	if slices.Contains(bundles, bundleAdmin) {
		return append(rules, bundleRules[bundleAdmin]...), nil
	}
	if slices.Contains(bundles, bundleRead) || slices.Contains(bundles, bundleWrite) {
		rules = append(rules, "~*", "&*")
		if slices.Contains(bundles, bundleRead) {
			rules = append(rules, "+@read")
		}
		if slices.Contains(bundles, bundleWrite) {
			rules = append(rules, "+@write")
		}
		rules = append(rules, "-@dangerous")
	}
	if slices.Contains(bundles, bundleMonitoring) {
		// INFO is categorized dangerous by Redis despite being metadata-only.
		// Restore only these named commands after the read/write carve-out.
		rules = append(rules, bundleRules[bundleMonitoring]...)
	}
	return rules, nil
}

// --- Опасные привилегии ---

// dangerousProbeCommands — команды классов ACL/CONFIG/FLUSHALL/SHUTDOWN и их
// ACL-категории (по официальной документации Redis 7). Правило опасно, если
// эффективно разрешает хотя бы одну из них. Категория slow включена честно:
// +@slow действительно даёт команду acl (проверено на живом Redis).
var dangerousProbeCommands = map[string][]string{
	"acl":       {"admin", "slow", "dangerous"},
	"config":    {"admin", "slow", "dangerous"},
	"shutdown":  {"admin", "slow", "dangerous"},
	"debug":     {"admin", "slow", "dangerous"},
	"module":    {"admin", "slow", "dangerous"},
	"replicaof": {"admin", "slow", "dangerous"},
	"slaveof":   {"admin", "slow", "dangerous"},
	"failover":  {"admin", "slow", "dangerous"},
	"cluster":   {"admin", "slow", "dangerous"},
	"flushall":  {"keyspace", "write", "slow", "dangerous"},
	"flushdb":   {"keyspace", "write", "slow", "dangerous"},
	"migrate":   {"keyspace", "write", "slow", "dangerous"},
	"restore":   {"keyspace", "write", "slow", "dangerous"},
	"swapdb":    {"keyspace", "write", "slow", "dangerous"},
}

// commandPermission — результат последовательной оценки правил селектора для
// одной команды: разрешена ли команда целиком и какие её subcommands
// разрешены отдельно.
type commandPermission struct {
	full bool
	subs map[string]bool
}

// evalCommand прогоняет правила селектора слева направо (порядок значим:
// «+@write -@dangerous» не разрешает FLUSHALL) и возвращает эффективное
// разрешение команды cmd с категориями cats.
func evalCommand(sel aclSelector, cmd string, cats []string) commandPermission {
	perm := commandPermission{subs: map[string]bool{}}
	for _, r := range sel.commands {
		switch {
		case r == "+@all":
			perm.full = true
		case r == "-@all":
			perm.full = false
			clear(perm.subs)
		case strings.HasPrefix(r, "+@"):
			if slices.Contains(cats, r[2:]) {
				perm.full = true
			}
		case strings.HasPrefix(r, "-@"):
			if slices.Contains(cats, r[2:]) {
				perm.full = false
				clear(perm.subs)
			}
		case r == "+"+cmd:
			perm.full = true
		case r == "-"+cmd:
			perm.full = false
			clear(perm.subs)
		case strings.HasPrefix(r, "+"+cmd+"|"):
			perm.subs[strings.TrimPrefix(r, "+"+cmd+"|")] = true
		case strings.HasPrefix(r, "-"+cmd+"|"):
			delete(perm.subs, strings.TrimPrefix(r, "-"+cmd+"|"))
		}
	}
	return perm
}

// aclAdminSubcommands — subcommands команды acl, без которых grantor не может
// управлять учётками, когда полная команда не разрешена.
var aclAdminSubcommands = []string{"whoami", "list", "getuser", "setuser", "deluser", "save"}

// aclAdminAllowed сообщает, может ли пользователь администрировать ACL:
// полная команда acl разрешена хотя бы одним селектором (root или
// дополнительным) либо разрешён весь необходимый набор subcommands.
func aclAdminAllowed(u aclUser) bool {
	for _, sel := range append([]aclSelector{u.root}, u.selectors...) {
		perm := evalCommand(sel, "acl", dangerousProbeCommands["acl"])
		if perm.full {
			return true
		}
		all := true
		for _, sub := range aclAdminSubcommands {
			if !perm.subs[sub] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// selectorDangerous сообщает, разрешает ли селектор хотя бы одну команду из
// dangerousProbeCommands целиком.
func selectorDangerous(sel aclSelector) bool {
	for cmd, cats := range dangerousProbeCommands {
		if evalCommand(sel, cmd, cats).full {
			return true
		}
	}
	return false
}

// userDangerous сообщает, опасны ли правила пользователя (root или любой
// селектор).
func userDangerous(u aclUser) bool {
	if selectorDangerous(u.root) {
		return true
	}
	for _, sel := range u.selectors {
		if selectorDangerous(sel) {
			return true
		}
	}
	return false
}

// --- Discovery ---

// Discover выполняет полную инвентаризацию: топология и версия (INFO,
// CLUSTER INFO), пользователи, permissions и bindings (ACL LIST). Все
// запросы только читают; мутаций discovery не выполняет.
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	if _, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential); err != nil {
		return nil, err
	}
	client, err := a.newClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("redis: discover: %w", err)
	}
	defer client.close()

	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: time.Now(),
	}

	info, err := client.serverAndReplicationInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis: discover: read info: %w", err)
	}
	snap.ServerVersion = info["redis_version"]
	snap.Topology = topologyFromInfo(info)
	snap.Topology["authentication_enabled"] = cfg.AuthMode != "none"
	if cfg.AuthMode == "none" {
		snap.Topology["authentication_disabled"] = true
	}
	snap.Topology["acl_persistence"] = client.aclPersistence(ctx)
	if info["redis_mode"] == "cluster" {
		// Best-effort: подробности кластера полезны, но их отсутствие не
		// должно ломать инвентаризацию.
		if clusterText, cerr := func() (string, error) {
			reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
			defer cancel()
			return client.rdb.ClusterInfo(reqCtx).Result()
		}(); cerr == nil {
			addClusterInfo(snap.Topology, parseInfo(clusterText))
		}
	}

	users, err := client.aclListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis: discover: acl list: %w", err)
	}

	permByID := map[string]adapter.ObservedPermission{}
	for _, p := range bundlePermissions() {
		permByID[p.ExternalID] = p
	}

	for _, u := range users {
		if u.name == defaultUserName {
			// Bootstrap-поверхность администратора: не managed (см.
			// doc-комментарий пакета).
			continue
		}
		snap.Accounts = append(snap.Accounts, adapter.ObservedAccount{
			Kind:           "login",
			EngineIdentity: u.name,
			Disabled:       !u.enabled,
			Attributes: map[string]any{
				"nopass":       u.noPass,
				"has_password": u.passwords > 0,
			},
		})

		bundles, managed, err := client.matchBundles(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("redis: discover: read ACL command metadata: %w", err)
		}
		if managed {
			for _, b := range bundles {
				snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
					AccountEngineIdentity: u.name,
					PermissionExternalID:  b,
					Attributes:            map[string]any{"bundle": b},
				})
			}
			continue
		}
		raw := rawACLPermission(u)
		if _, ok := permByID[raw.ExternalID]; !ok {
			permByID[raw.ExternalID] = raw
		}
		snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
			AccountEngineIdentity: u.name,
			PermissionExternalID:  raw.ExternalID,
			Attributes:            map[string]any{"rules": rulesSignature(u)},
		})
	}

	for _, p := range permByID {
		snap.Permissions = append(snap.Permissions, p)
	}
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)
	sortSnapshot(snap)
	return snap, nil
}

// bundlePermissions строит назначаемые permission bundles. Admin опасна:
// +@all — полный контроль над узлом, включая администрирование ACL.
func bundlePermissions() []adapter.ObservedPermission {
	perms := make([]adapter.ObservedPermission, 0, len(bundleRules))
	for _, name := range []string{bundleRead, bundleWrite, bundleMonitoring, bundleAdmin} {
		perms = append(perms, adapter.ObservedPermission{
			ExternalID: name,
			Name:       name,
			Assignable: true,
			Dangerous:  name == bundleAdmin,
			Attributes: map[string]any{
				"kind":  "bundle",
				"rules": strings.Join(bundleRules[name], " "),
			},
		})
	}
	return perms
}

// rawACLPermission строит неназначаемую observed permission для пользователя
// с unmanaged-правилами. ExternalID детерминирован по нормализованным
// правилам (без хэшей паролей), поэтому одинаковые правила у разных
// пользователей дают одну permission с несколькими bindings.
func rawACLPermission(u aclUser) adapter.ObservedPermission {
	sig := rulesSignature(u)
	id := rawPermissionPrefix + sig
	return adapter.ObservedPermission{
		ExternalID: id,
		Name:       id,
		Assignable: false,
		Dangerous:  userDangerous(u),
		Attributes: map[string]any{
			"kind":  "acl",
			"rules": sig,
		},
	}
}

// rulesSignature возвращает нормализованное текстовое представление правил
// пользователя: keys, channels, commands root-селектора, затем селекторы в
// скобках и нераспознанные токены. Хэши паролей и флаги не включаются.
func rulesSignature(u aclUser) string {
	parts := selectorSignature(u.root)
	for _, sel := range u.selectors {
		parts = append(parts, "("+strings.Join(selectorSignature(sel), " ")+")")
	}
	parts = append(parts, u.unknown...)
	return strings.Join(parts, " ")
}

// selectorSignature возвращает токены селектора в каноническом порядке
// keys/channels/commands.
func selectorSignature(sel aclSelector) []string {
	parts := make([]string, 0, len(sel.keys)+len(sel.channels)+len(sel.commands))
	parts = append(parts, sel.keys...)
	parts = append(parts, sel.channels...)
	parts = append(parts, sel.commands...)
	return parts
}

// --- Топология ---

// parseInfo разбирает текст INFO/CLUSTER INFO в карту ключ-значение.
func parseInfo(text string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = v
		}
	}
	return out
}

// topologyFromInfo строит Snapshot.Topology по INFO: redis_mode
// (standalone|cluster|sentinel) и роль репликации.
func topologyFromInfo(info map[string]string) map[string]any {
	mode := info["redis_mode"]
	if mode == "" {
		mode = "standalone"
	}
	out := map[string]any{adapterutil.TopologyKey: mode}
	if role := info["role"]; role != "" {
		out["role"] = role
	}
	if replicas := info["connected_slaves"]; replicas != "" && replicas != "0" {
		out["connected_replicas"] = replicas
	}
	return out
}

// addClusterInfo дополняет topology полями CLUSTER INFO.
func addClusterInfo(topology map[string]any, cluster map[string]string) {
	for _, k := range []string{"cluster_state", "cluster_size", "cluster_known_nodes"} {
		if v := cluster[k]; v != "" {
			topology[k] = v
		}
	}
}

// --- Утилиты ---

// sortedClone возвращает отсортированную копию среза.
func sortedClone(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// sortSnapshot приводит snapshot к детерминированному порядку: contract suite
// требует стабильности между повторными discovery.
func sortSnapshot(snap *adapter.Snapshot) {
	slices.SortFunc(snap.Accounts, func(a, b adapter.ObservedAccount) int {
		return strings.Compare(a.EngineIdentity, b.EngineIdentity)
	})
	slices.SortFunc(snap.Permissions, func(a, b adapter.ObservedPermission) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	slices.SortFunc(snap.Bindings, func(a, b adapter.ObservedBinding) int {
		if c := strings.Compare(a.AccountEngineIdentity, b.AccountEngineIdentity); c != 0 {
			return c
		}
		return strings.Compare(a.PermissionExternalID, b.PermissionExternalID)
	})
}
