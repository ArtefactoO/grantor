package adapterutil

import (
	"reflect"
	"testing"
)

func TestInheritedMemberships(t *testing.T) {
	cases := []struct {
		name   string
		direct []MembershipEdge
		want   []MembershipEdge
	}{
		{name: "empty"},
		{
			// Одно звено — наследовать нечего.
			name:   "direct membership only",
			direct: []MembershipEdge{{Role: "app_rw", Member: "alice"}},
		},
		{
			// alice -> app_rw -> app_ro: право app_ro получено через цепочку.
			name: "two links",
			direct: []MembershipEdge{
				{Role: "app_rw", Member: "alice"},
				{Role: "app_ro", Member: "app_rw"},
			},
			want: []MembershipEdge{{Role: "app_ro", Member: "alice"}},
		},
		{
			name: "three links",
			direct: []MembershipEdge{
				{Role: "a", Member: "alice"},
				{Role: "b", Member: "a"},
				{Role: "c", Member: "b"},
			},
			// Порядок — по member, затем по role: "a" идёт раньше "alice".
			want: []MembershipEdge{
				{Role: "c", Member: "a"},
				{Role: "b", Member: "alice"},
				{Role: "c", Member: "alice"},
			},
		},
		{
			// Роль, доступная и напрямую, и через цепочку, повторно не
			// выдаётся: прямое ребро уже есть в снапшоте.
			name: "role reachable both ways is not duplicated",
			direct: []MembershipEdge{
				{Role: "app_rw", Member: "alice"},
				{Role: "app_ro", Member: "alice"},
				{Role: "app_ro", Member: "app_rw"},
			},
		},
		{
			// Цикл не должен приводить к зацикливанию обхода.
			name: "cycle terminates",
			direct: []MembershipEdge{
				{Role: "a", Member: "b"},
				{Role: "b", Member: "a"},
				{Role: "a", Member: "alice"},
			},
			want: []MembershipEdge{{Role: "b", Member: "alice"}},
		},
		{
			// Самоссылка и пустые имена игнорируются: мусор в графе не
			// должен превращаться в права.
			name: "self reference and empty names are ignored",
			direct: []MembershipEdge{
				{Role: "a", Member: "a"},
				{Role: "", Member: "alice"},
				{Role: "b", Member: ""},
			},
		},
		{
			// Ромб: одна и та же роль достижима двумя путями — выдаётся один раз.
			name: "diamond yields one edge",
			direct: []MembershipEdge{
				{Role: "left", Member: "alice"},
				{Role: "right", Member: "alice"},
				{Role: "base", Member: "left"},
				{Role: "base", Member: "right"},
			},
			want: []MembershipEdge{{Role: "base", Member: "alice"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InheritedMemberships(tc.direct)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("InheritedMemberships = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Порядок обязан быть детерминированным: иначе каждый discovery выглядел бы
// как изменение снапшота.
func TestInheritedMembershipsIsDeterministic(t *testing.T) {
	direct := []MembershipEdge{
		{Role: "zulu", Member: "bob"},
		{Role: "alpha", Member: "zulu"},
		{Role: "mike", Member: "alice"},
		{Role: "alpha", Member: "mike"},
	}
	first := InheritedMemberships(direct)
	for range 5 {
		if got := InheritedMemberships(direct); !reflect.DeepEqual(got, first) {
			t.Fatalf("InheritedMemberships is unstable: %+v vs %+v", got, first)
		}
	}
	want := []MembershipEdge{
		{Role: "alpha", Member: "alice"},
		{Role: "alpha", Member: "bob"},
	}
	if !reflect.DeepEqual(first, want) {
		t.Errorf("InheritedMemberships = %+v, want %+v", first, want)
	}
}
