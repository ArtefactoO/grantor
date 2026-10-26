// Правила pg_hba подключения: GET /api/v1/connections/{id}/hba.
//
// В PostgreSQL доступ определяют три условия: сеть, правило pg_hba и SQL-права.
// Grantor управляет только третьим, поэтому выданная роль может не работать —
// и это самая частая причина «права выдали, а подключиться нельзя». Discovery
// складывает правила в Topology (read-only), а этот эндпоинт показывает их и
// называет учётки, для которых подходящего правила не нашлось.
//
// Ничего не мутируется: pg_hba.conf grantor не правит и править не может —
// файловый доступ к серверам за границей адаптера.
package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// hbaRule — одно правило pg_hba в форме, которую кладёт discovery.
type hbaRule struct {
	Number     int      `json:"number"`
	Type       string   `json:"type"`
	Databases  []string `json:"databases"`
	Users      []string `json:"users"`
	Address    string   `json:"address"`
	Netmask    string   `json:"netmask"`
	AuthMethod string   `json:"auth_method"`
	Options    []string `json:"options"`
	Error      string   `json:"error"`
}

// hbaResponse — тело GET /connections/{id}/hba.
type hbaResponse struct {
	// Supported=false означает «правила прочитать не удалось»: PostgreSQL
	// младше 15 либо у admin-учётки нет прав на pg_hba_file_rules. Это не
	// ошибка подключения, поэтому ответ 200 с пустым списком.
	Supported bool `json:"supported"`
	// Customized=true означает, что набор правил выходит за пределы
	// стандартного initdb-набора local/loopback. UI показывает вкладку HBA
	// только для реально настроенного файла, а не для пустого справочного
	// экрана на каждом PostgreSQL connection.
	Customized bool      `json:"customized"`
	Truncated  bool      `json:"truncated"`
	Rules      []hbaRule `json:"rules"`
	// UncoveredAccounts — engine identity живых login-аккаунтов, которым не
	// нашлось ни одного подходящего правила.
	UncoveredAccounts []string `json:"uncovered_accounts"`
}

// hbaIsCustomized отличает прикладной pg_hba от стандартного initdb-набора.
// pg_hba_file_rules не раскрывает исходный шаблон или checksum файла, поэтому
// сравнение семантическое: untouched-конфигурация адресует только local и
// loopback для all/postgres/replication. Любой конкретный пользователь,
// database, внешний адрес, option, hostssl/reject-строка или ошибка означает
// осознанную настройку и делает раздел полезным оператору.
func hbaIsCustomized(rules []hbaRule) bool {
	for i := range rules {
		if !isInitDBDefaultHBARule(rules[i]) {
			return true
		}
	}
	return false
}

func isInitDBDefaultHBARule(rule hbaRule) bool {
	if rule.Error != "" || rule.AuthMethod == "reject" || len(rule.Options) != 0 || len(rule.Databases) != 1 || len(rule.Users) != 1 {
		return false
	}
	database, user := rule.Databases[0], rule.Users[0]
	if database != "all" && database != "replication" {
		return false
	}

	switch rule.Type {
	case "local":
		if rule.Address != "" || rule.Netmask != "" {
			return false
		}
		// Debian/Ubuntu добавляют отдельную local all postgres строку перед
		// общей local all all; обе являются package default.
		return user == "all" || (database == "all" && user == "postgres")
	case "host":
		if user != "all" {
			return false
		}
		return isLoopbackHBAAddress(rule.Address, rule.Netmask)
	default:
		return false
	}
}

func isLoopbackHBAAddress(address, netmask string) bool {
	switch address {
	case "127.0.0.1":
		return netmask == "" || netmask == "255.255.255.255"
	case "::1":
		return netmask == "" || netmask == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	default:
		return false
	}
}

// hbaRulesFromTopology достаёт правила из Topology подключения. Отсутствие
// ключа — штатная ситуация (движок не postgres, старая версия, нет прав).
func hbaRulesFromTopology(topology json.RawMessage) (rules []hbaRule, truncated, supported bool) {
	if len(topology) == 0 {
		return nil, false, false
	}
	var decoded struct {
		Rules     []hbaRule `json:"hba_rules"`
		Truncated bool      `json:"hba_rules_truncated"`
	}
	if err := json.Unmarshal(topology, &decoded); err != nil {
		return nil, false, false
	}
	if decoded.Rules == nil {
		return nil, false, false
	}
	for i := range decoded.Rules {
		if len(decoded.Rules[i].Options) > 0 {
			decoded.Rules[i].Options = []string{"configured"}
		}
		if decoded.Rules[i].Error != "" {
			decoded.Rules[i].Error = "invalid_hba_rule"
		}
	}
	return decoded.Rules, decoded.Truncated, true
}

// ruleCoversUser сообщает, относится ли правило к учётной записи.
//
// Матчинг намеренно консервативный: базы и адреса не сопоставляются вовсе.
// Разбор CIDR и сопоставление database-списков без знания того, откуда именно
// подключается пользователь, дали бы ложные предупреждения, а ложное
// предупреждение о недоступности хуже отсутствия предупреждения — оно
// заставляет править работающую конфигурацию.
func ruleCoversUser(rule hbaRule, identity string, memberOf []string) bool {
	if rule.Error != "" || rule.AuthMethod == "reject" {
		return false
	}
	for _, user := range rule.Users {
		switch {
		case user == "all" || user == identity:
			return true
		case strings.HasPrefix(user, "+"):
			// +role покрывает членов роли, включая транзитивных.
			if slices.Contains(memberOf, strings.TrimPrefix(user, "+")) {
				return true
			}
		case strings.HasPrefix(user, "/"):
			// Регулярное выражение: интерпретировать его здесь не беремся,
			// поэтому считаем покрывающим — предупреждать наугад нельзя.
			return true
		}
	}
	return false
}

// hbaUncovered возвращает identity учёток, которым не нашлось правила.
// Пустой список правил не даёт находок: правила либо не читаются, либо
// действительно пусты, и в обоих случаях выводы делать не из чего.
func hbaUncovered(rules []hbaRule, accounts map[string][]string) []string {
	if len(rules) == 0 {
		return nil
	}
	var uncovered []string
	for identity, memberOf := range accounts {
		covered := false
		for _, rule := range rules {
			if ruleCoversUser(rule, identity, memberOf) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, identity)
		}
	}
	slices.Sort(uncovered)
	return uncovered
}

// listConnectionHBA отдаёт правила pg_hba подключения (viewer).
func (s *Server) listConnectionHBA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := s.requireConnection(w, r)
	if !ok {
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	rules, truncated, supported := hbaRulesFromTopology(conn.Topology)
	out := hbaResponse{
		Supported: supported, Customized: supported && hbaIsCustomized(rules),
		Truncated: truncated, Rules: rules,
	}
	if out.Rules == nil {
		out.Rules = []hbaRule{}
	}
	if !supported {
		out.UncoveredAccounts = []string{}
		respondJSON(w, http.StatusOK, out)
		return
	}

	accounts, err := s.inventory.ListAccounts(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	permissions, err := s.inventory.ListRolePermissions(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// permission вида role:<имя> — это и есть членство в роли PostgreSQL.
	roleByPermission := map[uuid.UUID]string{}
	for i := range permissions {
		if name, ok := strings.CutPrefix(permissions[i].ExternalID, "role:"); ok {
			roleByPermission[permissions[i].ID] = name
		}
	}

	bindings, err := s.inventory.ListRoleBindingsByConnection(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	rolesByAccount := map[uuid.UUID][]string{}
	for _, binding := range bindings {
		if binding.ObservedState != inventory.BindingPresent {
			continue
		}
		if role, ok := roleByPermission[binding.PermissionDefinitionID]; ok {
			rolesByAccount[binding.AccountID] = append(rolesByAccount[binding.AccountID], role)
		}
	}
	memberships := map[string][]string{}
	for i := range accounts {
		acct := accounts[i]
		if acct.Kind != inventory.AccountKindLogin || !inventory.IsLiveAccountStatus(acct.Status) {
			continue
		}
		// Членство берётся из инвентаря: adapter уже раскрыл его, включая
		// унаследованное через цепочки ролей.
		memberships[acct.EngineIdentity] = rolesByAccount[acct.ID]
	}
	out.UncoveredAccounts = hbaUncovered(rules, memberships)
	if out.UncoveredAccounts == nil {
		out.UncoveredAccounts = []string{}
	}
	respondJSON(w, http.StatusOK, out)
}
