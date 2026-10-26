package principals

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestTypeValid(t *testing.T) {
	for _, v := range []Type{TypeHuman, TypeService, TypeGroup} {
		if !v.Valid() {
			t.Errorf("Type(%q).Valid() = false, want true", v)
		}
	}
	for _, v := range []Type{"", "alien", "Human", "HUMAN"} {
		if v.Valid() {
			t.Errorf("Type(%q).Valid() = true, want false", v)
		}
	}
}

func TestStatusValid(t *testing.T) {
	for _, v := range []Status{StatusActive, StatusDisabled, StatusDeleted} {
		if !v.Valid() {
			t.Errorf("Status(%q).Valid() = false, want true", v)
		}
	}
	for _, v := range []Status{"", "Active", "removed"} {
		if v.Valid() {
			t.Errorf("Status(%q).Valid() = true, want false", v)
		}
	}
}

func TestExternalIdentityStatusValid(t *testing.T) {
	for _, v := range []ExternalIdentityStatus{
		ExternalIdentityActive,
		ExternalIdentityDisabled,
		ExternalIdentityDeleted,
	} {
		if !v.Valid() {
			t.Errorf("ExternalIdentityStatus(%q).Valid() = false, want true", v)
		}
	}
	for _, v := range []ExternalIdentityStatus{"", "missing", "Active"} {
		if v.Valid() {
			t.Errorf("ExternalIdentityStatus(%q).Valid() = true, want false", v)
		}
	}
}

// Create и SetStatus валидируют параметры до обращения к базе, поэтому
// невалидные случаи проверяются с nil Querier.
func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	cases := []struct {
		name    string
		params  CreateParams
		wantSub string
	}{
		{
			name:    "empty type",
			params:  CreateParams{DisplayName: "Alice"},
			wantSub: "invalid type",
		},
		{
			name:    "unknown type",
			params:  CreateParams{Type: "alien", DisplayName: "Alice"},
			wantSub: "invalid type",
		},
		{
			name:    "empty display name",
			params:  CreateParams{Type: TypeHuman},
			wantSub: "display name",
		},
		{
			name:    "whitespace display name",
			params:  CreateParams{Type: TypeHuman, DisplayName: "  \t"},
			wantSub: "display name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Create(ctx, nil, tc.params)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestSetStatusValidation(t *testing.T) {
	_, err := NewStore().SetStatus(context.Background(), nil, uuid.New(), "ghost")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid status") {
		t.Fatalf("error %q does not contain %q", err, "invalid status")
	}
}

func TestRecordExternalIdentityStatusValidation(t *testing.T) {
	_, err := NewStore().RecordExternalIdentityStatus(
		context.Background(), nil, uuid.New(), "missing", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid status") {
		t.Fatalf("error %q does not contain %q", err, "invalid status")
	}
}
