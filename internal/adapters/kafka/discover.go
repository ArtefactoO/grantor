package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// userPrincipalPrefix — префикс principal-типа User в Kafka ACL.
const userPrincipalPrefix = "User:"

// Префиксы external id. Bundle-permissions (topic-produce/topic-consume/
// cluster-admin), observed acl-permissions и topic-ресурсы живут в разных
// пространствах имён и не пересекаются.
const (
	topicResourcePrefix     = "topic:"
	producePermissionPrefix = "topic-produce:"
	consumePermissionPrefix = "topic-consume:"
	clusterAdminPermission  = "cluster-admin"
	aclPermissionPrefix     = "acl:"
)

// internalTopicNames — известные служебные topics, которые metadata может не
// пометить internal-флагом (Schema Registry, Redpanda).
var internalTopicNames = map[string]bool{
	"_schemas": true,
}

// aclEntry — нормализованная ACL-запись (одна строка DescribeAcls).
// Comparable: равенство записей — равенство структур.
type aclEntry struct {
	resourceType kmsg.ACLResourceType
	name         string
	pattern      kadm.ACLPattern
	principal    string // полный, например "User:app"
	host         string
	op           kadm.ACLOperation
	perm         kmsg.ACLPermissionType
}

// Discover выполняет полную инвентаризацию: топология и topics (Metadata),
// SCRAM-пользователи (DescribeUserScramCredentials — только на SCRAM-
// подключениях), ACL (DescribeAcls). На не-SCRAM кластере список
// SCRAM-пользователей пропускается, и аккаунты выводятся только из principals
// ACL (has_scram_credential=false). Все запросы только читают; мутаций
// discovery не выполняет.
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	client, err := a.newClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("kafka: discover: %w", err)
	}
	defer client.close()

	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: time.Now(),
	}

	meta, err := func() (kadm.Metadata, error) {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		return client.adm.Metadata(reqCtx)
	}()
	if err != nil {
		return nil, fmt.Errorf("kafka: discover: read metadata: %w", err)
	}
	snap.Topology = topologyFromMetadata(meta)
	snap.ServerVersion = serverVersionGuess(ctx, client)

	topicSet := map[string]bool{}
	for _, td := range meta.Topics.Sorted() {
		if td.Err != nil || isInternalTopic(td.Topic, td.IsInternal) {
			continue
		}
		topicSet[td.Topic] = true
		snap.Resources = append(snap.Resources, topicResource(td))
	}

	// SCRAM-пользователей перечисляем только на SCRAM-подключении: на
	// PLAIN/mTLS/none кластере SCRAM API может быть недоступен, а аккаунты
	// приходят из principals ACL.
	var scrams kadm.DescribedUserSCRAMs
	if client.auth.managesScram() {
		scrams, err = func() (kadm.DescribedUserSCRAMs, error) {
			reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
			defer cancel()
			return client.adm.DescribeUserSCRAMs(reqCtx)
		}()
		if err != nil {
			return nil, fmt.Errorf("kafka: discover: describe scram users: %w", err)
		}
	}

	// Выключенный ACL-авторизатор (SECURITY_DISABLED) — не ошибка: у кластера
	// просто нет ACL. Инвентаризируем topics (и SCRAM-пользователей, если
	// SCRAM), а bindings остаются пустыми.
	entries, aclAdminDisabled, err := client.describeACLsTolerant(ctx)
	if err != nil {
		return nil, fmt.Errorf("kafka: discover: describe acls: %w", err)
	}
	if aclAdminDisabled {
		snap.Topology[topologyACLAuthorizerKey] = aclAuthorizerDisabledValue
	}
	// Аутентификация клиентов — свойство самого подключения, а не ответа
	// брокера: анонимный кластер отвечает на всё и никакого признака не
	// возвращает.
	snap.Topology[adapterutil.AuthenticationKey] = client.auth.authenticatesClients()

	permByID := map[string]adapter.ObservedPermission{}
	for topic := range topicSet {
		for _, p := range topicPermissions(topic, !aclAdminDisabled) {
			permByID[p.ExternalID] = p
		}
	}
	permByID[clusterAdminPermission] = clusterAdminPermissionDef(!aclAdminDisabled)

	accounts := map[string]*adapter.ObservedAccount{}
	for _, u := range scrams.Sorted() {
		if u.Err != nil || u.User == "" {
			continue
		}
		mechs := make([]string, 0, len(u.CredInfos))
		for _, ci := range u.CredInfos {
			mechs = append(mechs, ci.Mechanism.String())
		}
		slices.Sort(mechs)
		accounts[u.User] = &adapter.ObservedAccount{
			Kind:           "login",
			EngineIdentity: u.User,
			Attributes: map[string]any{
				"has_scram_credential": true,
				"scram_mechanisms":     mechs,
			},
		}
	}

	byPrincipal := groupByPrincipal(entries)
	names := make([]string, 0, len(byPrincipal))
	for name := range byPrincipal {
		names = append(names, name)
		if _, ok := accounts[name]; !ok {
			accounts[name] = &adapter.ObservedAccount{
				Kind:           "login",
				EngineIdentity: name,
				Attributes: map[string]any{
					"has_scram_credential": false,
				},
			}
		}
	}
	slices.Sort(names)

	for _, name := range names {
		pentries := byPrincipal[name]
		if isDisabled(pentries, name) {
			accounts[name].Disabled = true
			pentries = withoutMarker(pentries, name)
		}
		bundles, leftover := matchBundles(name, pentries, topicSet)
		for _, b := range bundles {
			snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
				AccountEngineIdentity: name,
				PermissionExternalID:  b.permissionID,
				ScopeExternalID:       b.scopeID,
				Attributes:            b.attrs,
			})
		}
		snap.Bindings = append(snap.Bindings, observedACLBindings(name, leftover, topicSet, permByID)...)
	}

	for _, acc := range accounts {
		snap.Accounts = append(snap.Accounts, *acc)
	}
	for _, p := range permByID {
		snap.Permissions = append(snap.Permissions, p)
	}
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// describeAllACLs читает все ACL кластера (allow и deny, любые ресурсы,
// операции и hosts) и нормализует их в aclEntry. Ошибка фильтра (например,
// CLUSTER_AUTHORIZATION_FAILED или SECURITY_DISABLED) возвращается как есть —
// по ней вызывающий распознаёт нехватку привилегий или выключенный authorizer
// через errors.Is.
func (c *adminClient) describeAllACLs(ctx context.Context) ([]aclEntry, error) {
	b := kadm.NewACLs().
		AnyResource().
		ResourcePatternType(kadm.ACLPatternAny).
		Operations(kadm.OpAny).
		Allow().AllowHosts().
		Deny().DenyHosts()
	return c.describeACLs(ctx, b)
}

// describeACLsTolerant читает все ACL кластера, но терпит выключенный ACL-
// авторизатор: если брокер отвечает SECURITY_DISABLED (аутентификация есть, но
// authorizer не настроен), это не ошибка, а легитимный вариант конфигурации.
// Возвращает (nil, true, nil): ACL-администрирование недоступно, но кластер
// пригоден для инвентаризации. Прочие ошибки (в т.ч.
// CLUSTER_AUTHORIZATION_FAILED — нехватка прав admin, отдельная история)
// пробрасываются как есть.
func (c *adminClient) describeACLsTolerant(ctx context.Context) (entries []aclEntry, aclAdminDisabled bool, err error) {
	entries, err = c.describeAllACLs(ctx)
	if isSecurityDisabled(err) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return entries, false, nil
}

// isSecurityDisabled сообщает, что кластер вернул SECURITY_DISABLED (kerr code
// 54): SASL/mTLS-аутентификация настроена, но ACL-авторизатор на брокере не
// включён. Распознаётся через errors.Is по типизированному значению kerr, а не
// по тексту сообщения, и ловит ошибку и на уровне всего запроса, и на уровне
// результата фильтра DescribeAcls (kadm заворачивает per-result ошибку в
// цепочку %w, а kerr.ErrorForCode возвращает тот же singleton, поэтому
// errors.Is находит его в обоих случаях).
func isSecurityDisabled(err error) bool {
	return errors.Is(err, kerr.SecurityDisabled)
}

// principalACLs читает все ACL одного principal (allow и deny, любые hosts).
func (c *adminClient) principalACLs(ctx context.Context, user string) ([]aclEntry, error) {
	p := userPrincipal(user)
	b := kadm.NewACLs().
		AnyResource().
		ResourcePatternType(kadm.ACLPatternAny).
		Operations(kadm.OpAny).
		Allow(p).AllowHosts().
		Deny(p).DenyHosts()
	return c.describeACLs(ctx, b)
}

// principalACLsTolerant читает ACL principal, но терпит выключенный authorizer:
// SECURITY_DISABLED означает, что у кластера нет ACL, поэтому у principal их нет
// тоже -> (nil, nil). Используется на путях, которые не зависят от ACL и должны
// работать при authz-off (удаление SCRAM-учётки: ACL-части просто нет).
func (c *adminClient) principalACLsTolerant(ctx context.Context, user string) ([]aclEntry, error) {
	entries, err := c.principalACLs(ctx, user)
	if isSecurityDisabled(err) {
		return nil, nil
	}
	return entries, err
}

// describeACLs выполняет DescribeAcls по фильтру и собирает уникальные
// нормализованные записи.
func (c *adminClient) describeACLs(ctx context.Context, b *kadm.ACLBuilder) ([]aclEntry, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	results, err := c.describeACLsFn(reqCtx, b)
	if err != nil {
		return nil, err
	}
	seen := map[aclEntry]bool{}
	var out []aclEntry
	for _, r := range results {
		if r.Err != nil {
			return nil, fmt.Errorf("describe acls filter: %w", r.Err)
		}
		for _, d := range r.Described {
			e := aclEntry{
				resourceType: d.Type,
				name:         d.Name,
				pattern:      d.Pattern,
				principal:    d.Principal,
				host:         d.Host,
				op:           d.Operation,
				perm:         d.Permission,
			}
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// groupByPrincipal группирует записи по конкретным User-principals. ACL с
// wildcard principal (User:*) и не-User principals к аккаунтам не
// привязываются и отбрасываются (см. doc-комментарий пакета).
func groupByPrincipal(entries []aclEntry) map[string][]aclEntry {
	out := map[string][]aclEntry{}
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.principal, userPrincipalPrefix)
		if !ok || name == "" || name == wildcardName {
			continue
		}
		out[name] = append(out[name], e)
	}
	return out
}

// --- Permission bundles ---

// bundleBinding — распознанный binding permission bundle.
type bundleBinding struct {
	permissionID string
	scopeID      string
	attrs        map[string]any
}

// allowLiteral строит каноничную ALLOW-запись bundle: literal pattern,
// host "*".
func allowLiteral(user string, rtype kmsg.ACLResourceType, name string, op kadm.ACLOperation) aclEntry {
	return aclEntry{
		resourceType: rtype,
		name:         name,
		pattern:      kadm.ACLPatternLiteral,
		principal:    userPrincipal(user),
		host:         wildcardName,
		op:           op,
		perm:         kmsg.ACLPermissionTypeAllow,
	}
}

// produceEntries возвращает набор ACL bundle topic-produce:<topic>:
// WRITE+DESCRIBE на topic.
func produceEntries(user, topic string) []aclEntry {
	return []aclEntry{
		allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpWrite),
		allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpDescribe),
	}
}

// consumeEntries возвращает набор ACL bundle topic-consume:<topic>:
// READ+DESCRIBE на topic и READ на group "*".
func consumeEntries(user, topic string) []aclEntry {
	return []aclEntry{
		allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpRead),
		allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpDescribe),
		allowLiteral(user, kmsg.ACLResourceTypeGroup, wildcardName, kadm.OpRead),
	}
}

// clusterAdminEntries возвращает набор ACL bundle cluster-admin: ALL на
// cluster.
func clusterAdminEntries(user string) []aclEntry {
	return []aclEntry{
		allowLiteral(user, kmsg.ACLResourceTypeCluster, clusterResourceName, kadm.OpAll),
	}
}

// markerEntries возвращает DENY-маркер disable: DENY ALL на topic "*",
// group "*" и cluster (host "*"). Deny в Kafka сильнее allow, поэтому полный
// набор блокирует любые операции principal, не трогая его ALLOW ACL.
func markerEntries(user string) []aclEntry {
	p := userPrincipal(user)
	deny := func(rtype kmsg.ACLResourceType, name string) aclEntry {
		return aclEntry{
			resourceType: rtype,
			name:         name,
			pattern:      kadm.ACLPatternLiteral,
			principal:    p,
			host:         wildcardName,
			op:           kadm.OpAll,
			perm:         kmsg.ACLPermissionTypeDeny,
		}
	}
	return []aclEntry{
		deny(kmsg.ACLResourceTypeTopic, wildcardName),
		deny(kmsg.ACLResourceTypeGroup, wildcardName),
		deny(kmsg.ACLResourceTypeCluster, clusterResourceName),
	}
}

// isDisabled сообщает, присутствует ли полный DENY-маркер principal.
func isDisabled(entries []aclEntry, user string) bool {
	for _, m := range markerEntries(user) {
		if !slices.Contains(entries, m) {
			return false
		}
	}
	return true
}

// withoutMarker возвращает записи principal без записей DENY-маркера.
func withoutMarker(entries []aclEntry, user string) []aclEntry {
	marker := markerEntries(user)
	out := make([]aclEntry, 0, len(entries))
	for _, e := range entries {
		if !slices.Contains(marker, e) {
			out = append(out, e)
		}
	}
	return out
}

// matchBundles распознаёт permission bundles в наборе ACL principal и
// возвращает bindings вместе с необъяснёнными (unmanaged) записями. Запись
// может объясняться несколькими bundles (DESCRIBE topic разделяют produce и
// consume, READ на group "*" — все consume). Bundles распознаются только для
// topics из инвентаря: ACL на исчезнувший topic остаются unmanaged.
func matchBundles(user string, entries []aclEntry, topicSet map[string]bool) ([]bundleBinding, []aclEntry) {
	explained := make([]bool, len(entries))
	find := func(want aclEntry) int {
		return slices.Index(entries, want)
	}
	mark := func(idx ...int) {
		for _, i := range idx {
			explained[i] = true
		}
	}

	var bundles []bundleBinding
	if i := find(clusterAdminEntries(user)[0]); i >= 0 {
		mark(i)
		bundles = append(bundles, bundleBinding{
			permissionID: clusterAdminPermission,
			attrs:        map[string]any{"cluster": clusterResourceName, "operations": []string{"ALL"}},
		})
	}

	topics := make([]string, 0, len(topicSet))
	for t := range topicSet {
		topics = append(topics, t)
	}
	slices.Sort(topics)

	for _, t := range topics {
		w := find(allowLiteral(user, kmsg.ACLResourceTypeTopic, t, kadm.OpWrite))
		d := find(allowLiteral(user, kmsg.ACLResourceTypeTopic, t, kadm.OpDescribe))
		r := find(allowLiteral(user, kmsg.ACLResourceTypeTopic, t, kadm.OpRead))
		g := find(allowLiteral(user, kmsg.ACLResourceTypeGroup, wildcardName, kadm.OpRead))
		if w >= 0 && d >= 0 {
			mark(w, d)
			bundles = append(bundles, bundleBinding{
				permissionID: producePermissionID(t),
				scopeID:      topicExternalID(t),
				attrs:        map[string]any{"topic": t, "operations": []string{"WRITE", "DESCRIBE"}},
			})
		}
		if r >= 0 && d >= 0 && g >= 0 {
			mark(r, d, g)
			bundles = append(bundles, bundleBinding{
				permissionID: consumePermissionID(t),
				scopeID:      topicExternalID(t),
				attrs: map[string]any{
					"topic": t, "group": wildcardName,
					"operations": []string{"READ", "DESCRIBE", "GROUP_READ"},
				},
			})
		}
	}

	var leftover []aclEntry
	for i, e := range entries {
		if !explained[i] {
			leftover = append(leftover, e)
		}
	}
	return bundles, leftover
}

// observedACLBindings превращает необъяснённые ACL principal в bindings к
// неназначаемым observed permissions, агрегируя hosts одинаковых записей.
// Новые permission-определения дописываются в permByID.
func observedACLBindings(user string, leftover []aclEntry, topicSet map[string]bool,
	permByID map[string]adapter.ObservedPermission) []adapter.ObservedBinding {
	hostsByID := map[string][]string{}
	entryByID := map[string]aclEntry{}
	ids := make([]string, 0, len(leftover))
	for _, e := range leftover {
		id := aclPermissionID(e)
		if _, ok := entryByID[id]; !ok {
			entryByID[id] = e
			ids = append(ids, id)
		}
		if !slices.Contains(hostsByID[id], e.host) {
			hostsByID[id] = append(hostsByID[id], e.host)
		}
	}
	slices.Sort(ids)

	out := make([]adapter.ObservedBinding, 0, len(ids))
	for _, id := range ids {
		e := entryByID[id]
		scope := aclScopeID(e, topicSet)
		if _, ok := permByID[id]; !ok {
			permByID[id] = observedACLPermission(e, scope)
		}
		hosts := hostsByID[id]
		slices.Sort(hosts)
		out = append(out, adapter.ObservedBinding{
			AccountEngineIdentity: user,
			PermissionExternalID:  id,
			ScopeExternalID:       scope,
			Attributes: map[string]any{
				"resource_type": lower(e.resourceType.String()),
				"resource_name": e.name,
				"pattern":       lower(e.pattern.String()),
				"operation":     lower(e.op.String()),
				"permission":    lower(e.perm.String()),
				"hosts":         hosts,
			},
		})
	}
	return out
}

// observedACLPermission строит неназначаемое permission-определение для
// unmanaged ACL-записи.
func observedACLPermission(e aclEntry, scope string) adapter.ObservedPermission {
	id := aclPermissionID(e)
	return adapter.ObservedPermission{
		ExternalID:      id,
		Name:            id,
		ScopeExternalID: scope,
		Assignable:      false,
		Dangerous:       dangerousEntry(e),
		Attributes: map[string]any{
			"kind":          "acl",
			"resource_type": lower(e.resourceType.String()),
			"resource_name": e.name,
			"pattern":       lower(e.pattern.String()),
			"operation":     lower(e.op.String()),
			"permission":    lower(e.perm.String()),
		},
	}
}

// dangerousEntry классифицирует опасные ACL: cluster-ACL с операциями
// ALL/ALTER/CLUSTER_ACTION/IDEMPOTENT_WRITE (ALTER на cluster — это
// администрирование ACL и SCRAM) и ALL на wildcard topic. DENY-записи не
// опасны: они только ограничивают доступ.
func dangerousEntry(e aclEntry) bool {
	if e.perm != kmsg.ACLPermissionTypeAllow {
		return false
	}
	switch e.resourceType {
	case kmsg.ACLResourceTypeCluster:
		switch e.op {
		case kadm.OpAll, kadm.OpAlter, kadm.OpClusterAction, kadm.OpIdempotentWrite:
			return true
		}
		return false
	case kmsg.ACLResourceTypeTopic:
		return e.name == wildcardName && e.op == kadm.OpAll
	default:
		return false
	}
}

// topicPermissions строит назначаемые bundle-permissions одного topic.
func topicPermissions(topic string, assignable bool) []adapter.ObservedPermission {
	scope := topicExternalID(topic)
	return []adapter.ObservedPermission{
		{
			ExternalID:      producePermissionID(topic),
			Name:            producePermissionPrefix + topic,
			ScopeExternalID: scope,
			Assignable:      assignable,
			Attributes: map[string]any{
				"kind":       "bundle",
				"topic":      topic,
				"operations": []string{"WRITE", "DESCRIBE"},
			},
		},
		{
			ExternalID:      consumePermissionID(topic),
			Name:            consumePermissionPrefix + topic,
			ScopeExternalID: scope,
			Assignable:      assignable,
			Attributes: map[string]any{
				"kind":       "bundle",
				"topic":      topic,
				"group":      wildcardName,
				"operations": []string{"READ", "DESCRIBE", "GROUP_READ"},
			},
		},
	}
}

// clusterAdminPermissionDef строит permission cluster-admin (ALL на cluster).
// Она опасна: даёт полный контроль над кластером, включая администрирование
// ACL и SCRAM.
func clusterAdminPermissionDef(assignable bool) adapter.ObservedPermission {
	return adapter.ObservedPermission{
		ExternalID: clusterAdminPermission,
		Name:       clusterAdminPermission,
		Assignable: assignable,
		Dangerous:  true,
		Attributes: map[string]any{
			"kind":       "bundle",
			"cluster":    clusterResourceName,
			"operations": []string{"ALL"},
		},
	}
}

// topicResource строит ресурс kind topic.
func topicResource(td kadm.TopicDetail) adapter.ObservedResource {
	attrs := map[string]any{
		"partitions": len(td.Partitions),
	}
	if len(td.Partitions) > 0 {
		attrs["replication_factor"] = len(td.Partitions.Sorted()[0].Replicas)
	}
	id := topicExternalID(td.Topic)
	return adapter.ObservedResource{
		Kind:          "topic",
		ExternalID:    id,
		Name:          td.Topic,
		CanonicalPath: td.Topic,
		Attributes:    attrs,
		Fingerprint:   fingerprint("topic", id, attrs),
	}
}

// isInternalTopic сообщает, является ли topic служебным: internal-флаг
// metadata, префикс "__" (__consumer_offsets, __transaction_state,
// __redpanda*) или известные имена вроде _schemas.
func isInternalTopic(name string, isInternal bool) bool {
	return isInternal || strings.HasPrefix(name, "__") ||
		strings.HasPrefix(name, "_redpanda") || internalTopicNames[name]
}

// topologyFromMetadata определяет тип топологии по числу брокеров: один —
// standalone, несколько — cluster. Controller id, список брокеров и cluster
// id добавляются для наглядности.
func topologyFromMetadata(meta kadm.Metadata) map[string]any {
	brokers := make([]string, 0, len(meta.Brokers))
	for _, d := range meta.Brokers {
		brokers = append(brokers, fmt.Sprintf("%d@%s:%d", d.NodeID, d.Host, d.Port))
	}
	slices.Sort(brokers)
	topology := "standalone"
	if len(meta.Brokers) > 1 {
		topology = "cluster"
	}
	out := map[string]any{
		adapterutil.TopologyKey: topology,
		"broker_count":          len(meta.Brokers),
		"controller":            int(meta.Controller),
	}
	if len(brokers) > 0 {
		out["brokers"] = brokers
	}
	if meta.Cluster != "" {
		out["cluster_id"] = meta.Cluster
	}
	return out
}

// serverVersionGuess возвращает best-effort догадку версии Kafka-протокола по
// ApiVersions первого доступного брокера; при ошибке — пустую строку.
func serverVersionGuess(ctx context.Context, client *adminClient) string {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	vs, err := client.adm.ApiVersions(reqCtx)
	if err != nil {
		return ""
	}
	for _, v := range vs.Sorted() {
		if v.Err == nil {
			return v.VersionGuess()
		}
	}
	return ""
}

// --- External IDs и утилиты ---

// userPrincipal возвращает полный Kafka principal пользователя.
func userPrincipal(user string) string { return userPrincipalPrefix + user }

// topicExternalID возвращает external id topic-ресурса.
func topicExternalID(topic string) string { return topicResourcePrefix + topic }

// producePermissionID возвращает external id bundle topic-produce.
func producePermissionID(topic string) string { return producePermissionPrefix + topic }

// consumePermissionID возвращает external id bundle topic-consume.
func consumePermissionID(topic string) string { return consumePermissionPrefix + topic }

// aclPermissionID возвращает external id observed acl-permission. Имена
// topic в Kafka не содержат ":", поэтому id однозначен для topic-ресурсов;
// возможные коллизии по прочим ресурсам дедуплицируются картой permissions.
func aclPermissionID(e aclEntry) string {
	return aclPermissionPrefix + strings.Join([]string{
		lower(e.resourceType.String()),
		lower(e.pattern.String()),
		e.name,
		lower(e.op.String()),
		lower(e.perm.String()),
	}, ":")
}

// aclScopeID возвращает scope observed acl-permission: literal topic из
// инвентаря — его external id, всё остальное — cluster-wide (пусто).
func aclScopeID(e aclEntry, topicSet map[string]bool) string {
	if e.resourceType == kmsg.ACLResourceTypeTopic &&
		e.pattern == kadm.ACLPatternLiteral && topicSet[e.name] {
		return topicExternalID(e.name)
	}
	return ""
}

// lower приводит имя enum к нижнему регистру для attributes и external ids.
func lower(s string) string { return strings.ToLower(s) }

// fingerprint строит стабильный отпечаток ресурса по kind, external id и
// атрибутам. Ключи атрибутов сортируются, а значения кодируются каноничным
// JSON, поэтому одно и то же содержимое всегда даёт один и тот же отпечаток
// независимо от порядка map.
func fingerprint(kind, externalID string, attrs map[string]any) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(attrs)+2)
	parts = append(parts, kind, externalID)
	for _, k := range keys {
		enc, err := json.Marshal(attrs[k])
		if err != nil {
			enc = []byte(fmt.Sprintf("%v", attrs[k]))
		}
		parts = append(parts, k+"="+string(enc))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])[:16]
}

// sortSnapshot приводит snapshot к детерминированному порядку: contract suite
// требует стабильности между повторными discovery.
func sortSnapshot(snap *adapter.Snapshot) {
	slices.SortFunc(snap.Resources, func(a, b adapter.ObservedResource) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
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
		if c := strings.Compare(a.PermissionExternalID, b.PermissionExternalID); c != 0 {
			return c
		}
		return strings.Compare(a.ScopeExternalID, b.ScopeExternalID)
	})
}
