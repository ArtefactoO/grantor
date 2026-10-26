package adaptertest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// RandomHex возвращает n случайных байт в hex — удобно для уникальных имён
// эфемерных объектов (учёток, ролей) в engine integration-тестах. Общий хелпер
// вместо копии в каждом пакете adapters/*.
func RandomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(buf)
}

// PlanApplyVerify прогоняет полный lifecycle одного изменения: Plan → Apply →
// Verify. Каждый шаг Apply обязан завершиться StepApplied или StepSkipped, а
// Verify — подтвердить целевое состояние. Общий хелпер вместо копии в каждом
// пакете adapters/*.
func PlanApplyVerify(ctx context.Context, t *testing.T, ad adapter.Adapter, change adapter.DesiredChange) {
	t.Helper()
	plan, err := ad.Plan(ctx, change)
	if err != nil {
		t.Fatalf("Plan(%s): %v", change.Kind, err)
	}
	res, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply(%s): %v", change.Kind, err)
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepApplied && s.Status != adapter.StepSkipped {
			t.Fatalf("Apply(%s): step %q finished with %q: %s", change.Kind, s.Step.Kind, s.Status, s.Error)
		}
	}
	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		t.Fatalf("Verify(%s): %v", change.Kind, err)
	}
	if !ver.Verified {
		t.Fatalf("Verify(%s): not verified: %s", change.Kind, ver.Details)
	}
}
