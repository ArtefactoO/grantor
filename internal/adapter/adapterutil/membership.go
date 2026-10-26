package adapterutil

import "sort"

// Раскрытие транзитивных членств в ролях.
//
// Движки с иерархией ролей (postgres, mysql, clickhouse, mongodb) отдают
// discovery только ПРЯМЫЕ рёбра «роль → член». Права, полученные через
// цепочку ролей, в инвентаре не появлялись вовсе: аккаунт, входящий в роль
// app_rw, которая входит в app_ro, выглядел как имеющий только app_rw, хотя
// фактически обладает и правами app_ro. Оператор не видел ни самого права,
// ни того, откуда оно взялось.
//
// Раскрытие вынесено в общий пакет: граф у всех четырёх движков один и тот
// же (ориентированные рёбра членства), различается только способ его
// прочитать. Функция чистая — движковых знаний не содержит и тестируется
// без поднятого движка.

// MembershipEdge — прямое ребро членства: member входит в role.
type MembershipEdge struct {
	// Role — роль, в которую входят.
	Role string
	// Member — тот, кто входит: учётная запись или другая роль.
	Member string
}

// InheritedMemberships возвращает рёбра, которых нет среди прямых, но
// которые следуют из цепочек: member входит в role через одну или несколько
// промежуточных ролей.
//
// Результат детерминирован (отсортирован по member, затем по role) — иначе
// каждый discovery выглядел бы как изменение снапшота.
//
// Циклы безопасны: обход помнит посещённые узлы. PostgreSQL циклы запрещает,
// но полагаться на это в общей функции нельзя — другие движки таких гарантий
// не дают, а зацикливание discovery хуже неполного результата.
func InheritedMemberships(direct []MembershipEdge) []MembershipEdge {
	if len(direct) == 0 {
		return nil
	}

	// roles[x] — роли, в которые непосредственно входит x.
	roles := make(map[string][]string, len(direct))
	// isDirect — множество прямых рёбер: их повторять не нужно, они уже
	// присутствуют в снапшоте как обычные bindings.
	isDirect := make(map[MembershipEdge]bool, len(direct))
	members := make([]string, 0, len(direct))
	seenMember := make(map[string]bool, len(direct))

	for _, e := range direct {
		if e.Role == "" || e.Member == "" || e.Role == e.Member {
			continue
		}
		roles[e.Member] = append(roles[e.Member], e.Role)
		isDirect[e] = true
		if !seenMember[e.Member] {
			seenMember[e.Member] = true
			members = append(members, e.Member)
		}
	}

	var out []MembershipEdge
	for _, member := range members {
		visited := map[string]bool{member: true}
		// Стартуем с прямых ролей члена, но в результат кладём только то,
		// что найдено ГЛУБЖЕ них: прямые рёбра уже есть в снапшоте.
		queue := append([]string(nil), roles[member]...)
		for _, r := range queue {
			visited[r] = true
		}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for _, parent := range roles[current] {
				if visited[parent] {
					continue
				}
				visited[parent] = true
				queue = append(queue, parent)
				edge := MembershipEdge{Role: parent, Member: member}
				if isDirect[edge] {
					continue
				}
				out = append(out, edge)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Member != out[j].Member {
			return out[i].Member < out[j].Member
		}
		return out[i].Role < out[j].Role
	})
	return out
}
