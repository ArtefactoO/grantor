package directory

import (
	"context"
	"testing"
)

// TestStaticStatuses проверяет семантику mock-провайдера: disabled/missing по
// спискам, остальные active, запись для каждого запрошенного субъекта.
func TestStaticStatuses(t *testing.T) {
	p := NewStatic(
		[]string{" carol@grantor.dev ", "dave@grantor.dev", ""},
		[]string{"bob@grantor.dev", "dave@grantor.dev"},
	)

	got, err := p.Statuses(context.Background(), []string{
		"alice@grantor.dev",
		"bob@grantor.dev",
		"carol@grantor.dev",
		"dave@grantor.dev",
	})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}

	want := map[string]Status{
		"alice@grantor.dev": StatusActive,
		"bob@grantor.dev":   StatusMissing,
		// Пробелы в списке обрезаются.
		"carol@grantor.dev": StatusDisabled,
		// missing приоритетнее disabled при пересечении списков.
		"dave@grantor.dev": StatusMissing,
	}
	if len(got) != len(want) {
		t.Fatalf("Statuses returned %d entries, want %d: %v", len(got), len(want), got)
	}
	for subj, st := range want {
		if got[subj] != st {
			t.Errorf("Statuses[%q] = %q, want %q", subj, got[subj], st)
		}
	}
}

// TestStaticEmpty проверяет, что пустой провайдер считает всех активными.
func TestStaticEmpty(t *testing.T) {
	p := NewStatic(nil, nil)
	got, err := p.Statuses(context.Background(), []string{"anyone@grantor.dev"})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if got["anyone@grantor.dev"] != StatusActive {
		t.Errorf("Statuses = %q, want %q", got["anyone@grantor.dev"], StatusActive)
	}
}
