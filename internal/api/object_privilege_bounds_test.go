package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestObjectPrivilegePublicProjectionIsBoundedAndKeepsColumnScope(t *testing.T) {
	for _, test := range []struct {
		name, kind, column string
		raw                any
		want               []string
		truncated          bool
	}{
		{"empty", "table", "", nil, []string{}, false},
		{"deduplicate", "table", "", []any{"UPDATE", "SELECT", "SELECT"}, []string{"SELECT", "UPDATE"}, false},
		{"unknown", "table", "", []any{"SELECT", "unrecognized", 12, strings.Repeat("x", 4096)}, []string{"SELECT"}, true},
		{"table excludes column grant", "table", "", []any{"SELECT (private_column)", "TRUNCATE"}, []string{"TRUNCATE"}, true},
		{"column matches selected column", "table", "selected", []any{"SELECT (selected)", "SELECT (other)", "UPDATE", "UPDATE (selected)"}, []string{"SELECT", "UPDATE"}, true},
		{"wrong shape", "table", "", map[string]any{"SELECT": true}, []string{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, truncated := boundedObjectPublicPrivileges(test.raw, test.kind, test.column)
			if !reflect.DeepEqual(got, test.want) || truncated != test.truncated {
				t.Fatalf("PUBLIC projection = %v/%t, want %v/%t", got, truncated, test.want, test.truncated)
			}
			if len(got) > 30 {
				t.Fatal("PUBLIC projection exceeded its entry bound")
			}
			for _, value := range got {
				if len(value) > 32 {
					t.Fatal("PUBLIC projection exceeded its privilege-name bound")
				}
			}
		})
	}
}
