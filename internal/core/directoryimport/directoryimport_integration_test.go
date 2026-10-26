//go:build integration

package directoryimport

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

const provider = "itest-authentik"

// roster строит static-провайдер с перечислимым списком субъектов.
func roster(subjects []string, disabled, missing []string) directory.Provider {
	return directory.NewStatic(disabled, missing).WithRoster(subjects)
}

// lookupOnly — провайдер без перечисления: умеет только сверять статусы.
// Нужен, чтобы проверить деградацию импорта на таком каталоге.
type lookupOnly struct{}

func (lookupOnly) Statuses(_ context.Context, subjects []string) (map[string]directory.Status, error) {
	out := make(map[string]directory.Status, len(subjects))
	for _, s := range subjects {
		out[s] = directory.StatusActive
	}
	return out, nil
}

func TestIntegrationImportSubjectsCreatesPrincipals(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	subject := "ivan-" + uuid.NewString()[:8] + "@example.com"

	svc := New(pool, roster([]string{subject}, nil, nil), provider)
	result, err := svc.ImportSubjects(ctx, []string{subject})
	if err != nil {
		t.Fatalf("ImportSubjects: %v", err)
	}
	if len(result.Created) != 1 {
		t.Fatalf("created = %d, want 1", len(result.Created))
	}
	p := result.Created[0]
	if p.ExternalProvider != provider || p.ExternalSubject != subject {
		t.Errorf("external identity = %s/%s, want %s/%s",
			p.ExternalProvider, p.ExternalSubject, provider, subject)
	}
	if p.Type != principals.TypeHuman {
		t.Errorf("type = %q, want human", p.Type)
	}
	// Зеркало статуса пишется сразу из уже полученного ответа каталога:
	// иначе принципал висит «Not checked» до первого фонового поллинга.
	if p.ExternalIdentityStatus == nil || *p.ExternalIdentityStatus != principals.ExternalIdentityActive {
		t.Errorf("external identity status = %v, want %q",
			p.ExternalIdentityStatus, principals.ExternalIdentityActive)
	}
	if p.ExternalIdentityCheckedAt == nil {
		t.Error("external identity checked_at is nil, want set")
	}
}

// Каталог опрашивают периодически, и импорт обязан переживать повтор:
// второй прогон не должен создавать дубль и не должен считаться ошибкой.
func TestIntegrationImportIsIdempotent(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	subject := "repeat-" + uuid.NewString()[:8] + "@example.com"
	svc := New(pool, roster([]string{subject}, nil, nil), provider)

	if _, err := svc.ImportSubjects(ctx, []string{subject}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	second, err := svc.ImportSubjects(ctx, []string{subject})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if len(second.Created) != 0 {
		t.Errorf("created on repeat = %d, want 0", len(second.Created))
	}
	if len(second.SkippedExisting) != 1 {
		t.Errorf("skipped_existing = %v, want the subject reported as already imported", second.SkippedExisting)
	}
}

// Субъект, которого каталог не знает, заводить нельзя: такой принципал
// сразу подлежал бы offboarding-детекции, то есть создавался бы мусор.
func TestIntegrationImportSkipsMissingSubjects(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	known := "known-" + uuid.NewString()[:8] + "@example.com"
	gone := "gone-" + uuid.NewString()[:8] + "@example.com"

	svc := New(pool, roster([]string{known}, nil, []string{gone}), provider)
	result, err := svc.ImportSubjects(ctx, []string{known, gone})
	if err != nil {
		t.Fatalf("ImportSubjects: %v", err)
	}
	if len(result.Created) != 1 || result.Created[0].ExternalSubject != known {
		t.Errorf("created = %+v, want only the known subject", result.Created)
	}
	if len(result.SkippedMissing) != 1 || result.SkippedMissing[0] != gone {
		t.Errorf("skipped_missing = %v, want the unknown subject", result.SkippedMissing)
	}
}

// Массовая загрузка обязана заводить ровно то же, что явный список из
// перечисления: разные пути не должны давать разный результат.
func TestIntegrationImportAllMatchesExplicitList(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	prefix := "bulk-" + uuid.NewString()[:8]
	subjects := []string{prefix + "-a@example.com", prefix + "-b@example.com"}

	svc := New(pool, roster(subjects, nil, nil), provider)
	result, err := svc.ImportAll(ctx, prefix, 10)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(result.Created) != 2 {
		t.Fatalf("created = %d, want 2", len(result.Created))
	}
}

// Поиск помечает уже заведённых, чтобы оператору не приходилось выяснять
// это самостоятельно.
func TestIntegrationSearchMarksImported(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	prefix := "mark-" + uuid.NewString()[:8]
	imported := prefix + "-in@example.com"
	fresh := prefix + "-out@example.com"

	svc := New(pool, roster([]string{imported, fresh}, nil, nil), provider)
	if _, err := svc.ImportSubjects(ctx, []string{imported}); err != nil {
		t.Fatalf("seed import: %v", err)
	}

	candidates, err := svc.Search(ctx, prefix, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	got := map[string]bool{}
	for _, c := range candidates {
		got[c.Subject] = c.Imported
	}
	if !got[imported] {
		t.Errorf("candidate %q: imported = false, want true", imported)
	}
	if got[fresh] {
		t.Errorf("candidate %q: imported = true, want false", fresh)
	}
}

// Выключенный в каталоге заводится сразу выключенным: выдавать доступ
// человеку, которого каталог уже заблокировал, нельзя без осознанного
// включения. Расхождение поймал прогон на живом Authentik — мок проверял
// только отсутствующих.
func TestIntegrationImportedDisabledSubjectIsDisabled(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	blocked := "blocked-" + uuid.NewString()[:8] + "@example.com"

	svc := New(pool, roster([]string{blocked}, []string{blocked}, nil), provider)
	result, err := svc.ImportSubjects(ctx, []string{blocked})
	if err != nil {
		t.Fatalf("ImportSubjects: %v", err)
	}
	if len(result.Created) != 1 {
		t.Fatalf("created = %d, want 1", len(result.Created))
	}
	if got := result.Created[0].Status; got != principals.StatusDisabled {
		t.Errorf("status = %q, want disabled", got)
	}
}

// Каталог без перечисления импорт не поддерживает — и это должно быть
// видно вызывающему явной ошибкой, а не пустой выдачей.
func TestIntegrationSearchUnsupported(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	svc := New(pool, lookupOnly{}, provider)

	if svc.Enabled() {
		t.Error("Enabled = true for a provider without search")
	}
	if _, err := svc.Search(ctx, "", 10); !errors.Is(err, ErrSearchUnsupported) {
		t.Errorf("Search error = %v, want ErrSearchUnsupported", err)
	}
}

// Без каталога импорт выключен: методы обязаны сказать это прямо.
func TestIntegrationNotConfigured(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	svc := New(pool, nil, provider)

	if svc.Enabled() {
		t.Error("Enabled = true without a directory")
	}
	if _, err := svc.ImportSubjects(ctx, []string{"a@example.com"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("ImportSubjects error = %v, want ErrNotConfigured", err)
	}
}
