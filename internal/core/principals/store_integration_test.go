//go:build integration

// Integration-тесты store принципалов против реального PostgreSQL
// (pgtest, GRANTOR_TEST_DB_DSN). Проверяются и методы inventory,
// связанные с принципалами: счётчик в List обязан совпадать с
// ListAccountsByPrincipal.
package principals_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// listLimit — лимит выборки List в тестах: общая тестовая база может
// содержать принципалов других тестов и прогонов.
const listLimit = 100000

// listItem находит принципала в списке по id.
func listItem(t *testing.T, items []principals.ListItem, id uuid.UUID) principals.ListItem {
	t.Helper()
	for i := range items {
		if items[i].ID == id {
			return items[i]
		}
	}
	t.Fatalf("principal %s not found in list of %d", id, len(items))
	return principals.ListItem{}
}

func TestPrincipalsStoreFlow(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := principals.NewStore()

	// Create: статус active, атрибуты по умолчанию — пустой объект.
	subject := "sub-" + uuid.NewString()
	human, err := store.Create(ctx, pool, principals.CreateParams{
		Type:             principals.TypeHuman,
		DisplayName:      "itest-human-" + uuid.NewString(),
		ExternalProvider: "dex",
		ExternalSubject:  subject,
	})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	if human.Type != principals.TypeHuman || human.Status != principals.StatusActive {
		t.Errorf("created type/status = %q/%q, want human/active", human.Type, human.Status)
	}
	if string(human.Attributes) != "{}" {
		t.Errorf("created attributes = %s, want {}", human.Attributes)
	}
	if human.CreatedAt.IsZero() || human.UpdatedAt.IsZero() {
		t.Error("created timestamps are zero")
	}

	// Повторная внешняя identity — ErrAlreadyExists.
	if _, err := store.Create(ctx, pool, principals.CreateParams{
		Type:             principals.TypeHuman,
		DisplayName:      "itest-dup-" + uuid.NewString(),
		ExternalProvider: "dex",
		ExternalSubject:  subject,
	}); !errors.Is(err, principals.ErrAlreadyExists) {
		t.Errorf("duplicate identity error = %v, want ErrAlreadyExists", err)
	}

	// Второй (локальный) принципал без внешней identity.
	service, err := store.Create(ctx, pool, principals.CreateParams{
		Type:        principals.TypeService,
		DisplayName: "itest-svc-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	// Get.
	got, err := store.Get(ctx, pool, human.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DisplayName != human.DisplayName || got.ExternalSubject != subject {
		t.Errorf("get = %q/%q, want %q/%q", got.DisplayName, got.ExternalSubject, human.DisplayName, subject)
	}
	if _, err := store.Get(ctx, pool, uuid.New()); !errors.Is(err, principals.ErrNotFound) {
		t.Errorf("get missing error = %v, want ErrNotFound", err)
	}

	// Счётчик accounts в List: два аккаунта у human, ноль у service.
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-principals-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	inv := inventory.NewStore()
	accountIDs := make([]uuid.UUID, 0, 2)
	for i := 0; i < 2; i++ {
		acct, err := inv.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
			ConnectionID:   conn.ID,
			EngineIdentity: fmt.Sprintf("itest_pr_%d_%s", i, uuid.NewString()[:8]),
			PrincipalID:    &human.ID,
		})
		if err != nil {
			t.Fatalf("create managed account %d: %v", i, err)
		}
		accountIDs = append(accountIDs, acct.ID)
	}

	items, err := store.List(ctx, pool, listLimit, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := listItem(t, items, human.ID).AccountsCount; got != 2 {
		t.Errorf("human accounts count = %d, want 2", got)
	}
	if got := listItem(t, items, service.ID).AccountsCount; got != 0 {
		t.Errorf("service accounts count = %d, want 0", got)
	}

	// Limit применяется.
	limited, err := store.List(ctx, pool, 1, 0)
	if err != nil {
		t.Fatalf("list with limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("limited list = %d items, want 1", len(limited))
	}

	// ListAccountsByPrincipal согласован со счётчиком.
	accounts, err := inv.ListAccountsByPrincipal(ctx, pool, human.ID)
	if err != nil {
		t.Fatalf("list accounts by principal: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("accounts by principal = %d, want 2", len(accounts))
	}

	// LinkAccountPrincipal: unlink, перепривязка, ошибки ссылок.
	unlinked, err := inv.LinkAccountPrincipal(ctx, pool, accountIDs[0], nil)
	if err != nil {
		t.Fatalf("unlink account: %v", err)
	}
	if unlinked.PrincipalID != nil {
		t.Errorf("unlinked principal_id = %v, want nil", unlinked.PrincipalID)
	}
	relinked, err := inv.LinkAccountPrincipal(ctx, pool, accountIDs[0], &service.ID)
	if err != nil {
		t.Fatalf("relink account: %v", err)
	}
	if relinked.PrincipalID == nil || *relinked.PrincipalID != service.ID {
		t.Errorf("relinked principal_id = %v, want %s", relinked.PrincipalID, service.ID)
	}
	if _, err := inv.LinkAccountPrincipal(ctx, pool, uuid.New(), &service.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("link missing account error = %v, want ErrNotFound", err)
	}
	ghost := uuid.New()
	if _, err := inv.LinkAccountPrincipal(ctx, pool, accountIDs[0], &ghost); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("link missing principal error = %v, want ErrNotFound", err)
	}

	// Deleted-аккаунты не входят ни в счётчик, ни в список.
	if err := inv.MarkAccountDeleted(ctx, pool, accountIDs[1], "itest@grantor.dev", ""); err != nil {
		t.Fatalf("mark account deleted: %v", err)
	}
	items, err = store.List(ctx, pool, listLimit, 0)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if got := listItem(t, items, human.ID).AccountsCount; got != 0 {
		t.Errorf("human accounts count after relink+delete = %d, want 0", got)
	}
	if got := listItem(t, items, service.ID).AccountsCount; got != 1 {
		t.Errorf("service accounts count after relink = %d, want 1", got)
	}
	accounts, err = inv.ListAccountsByPrincipal(ctx, pool, human.ID)
	if err != nil {
		t.Fatalf("list accounts by principal after delete: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("human accounts after relink+delete = %d, want 0", len(accounts))
	}

	// SetStatus: disable, enable, not found.
	disabled, err := store.SetStatus(ctx, pool, human.ID, principals.StatusDisabled)
	if err != nil {
		t.Fatalf("set status disabled: %v", err)
	}
	if disabled.Status != principals.StatusDisabled {
		t.Errorf("status = %q, want disabled", disabled.Status)
	}
	enabled, err := store.SetStatus(ctx, pool, human.ID, principals.StatusActive)
	if err != nil {
		t.Fatalf("set status active: %v", err)
	}
	if enabled.Status != principals.StatusActive {
		t.Errorf("status = %q, want active", enabled.Status)
	}
	if _, err := store.SetStatus(ctx, pool, uuid.New(), principals.StatusDisabled); !errors.Is(err, principals.ErrNotFound) {
		t.Errorf("set status missing error = %v, want ErrNotFound", err)
	}

	// Зеркало внешней identity живёт отдельно от локального lifecycle.
	// checked_at обновляется на каждом успешном наблюдении, changed_at —
	// только при фактической смене внешнего статуса.
	update, err := store.RecordExternalIdentityStatus(
		ctx, pool, human.ID, principals.ExternalIdentityActive, false)
	if err != nil {
		t.Fatalf("record external active: %v", err)
	}
	external := update.Principal
	transitioned := update.LocallyDisabled
	if !update.StatusChanged || update.PreviousStatus != nil {
		t.Errorf("first observation change = %v previous %v, want true/nil",
			update.StatusChanged, update.PreviousStatus)
	}
	if transitioned || external.Status != principals.StatusActive {
		t.Errorf("external active transitioned/local status = %v/%q, want false/active",
			transitioned, external.Status)
	}
	if external.ExternalIdentityStatus == nil ||
		*external.ExternalIdentityStatus != principals.ExternalIdentityActive ||
		external.ExternalIdentityCheckedAt == nil || external.ExternalIdentityStatusChangedAt == nil {
		t.Fatalf("external active mirror incomplete: %+v", external)
	}

	marker := time.Date(2000, time.January, 2, 3, 4, 5, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
		update principals set
			external_identity_checked_at = $2,
			external_identity_status_changed_at = $2
		where id = $1`, human.ID, marker); err != nil {
		t.Fatalf("set external identity timestamp marker: %v", err)
	}
	update, err = store.RecordExternalIdentityStatus(
		ctx, pool, human.ID, principals.ExternalIdentityActive, false)
	if err != nil {
		t.Fatalf("record repeated external active: %v", err)
	}
	external = update.Principal
	transitioned = update.LocallyDisabled
	if update.StatusChanged || update.PreviousStatus == nil ||
		*update.PreviousStatus != principals.ExternalIdentityActive {
		t.Errorf("repeated observation change = %v previous %v, want false/active",
			update.StatusChanged, update.PreviousStatus)
	}
	if transitioned || external.ExternalIdentityCheckedAt == nil ||
		!external.ExternalIdentityCheckedAt.After(marker) ||
		external.ExternalIdentityStatusChangedAt == nil ||
		!external.ExternalIdentityStatusChangedAt.Equal(marker) {
		t.Errorf("repeated external active timestamps/transition = checked %v changed %v transitioned %v",
			external.ExternalIdentityCheckedAt, external.ExternalIdentityStatusChangedAt, transitioned)
	}

	update, err = store.RecordExternalIdentityStatus(
		ctx, pool, human.ID, principals.ExternalIdentityDisabled, true)
	if err != nil {
		t.Fatalf("record external disabled: %v", err)
	}
	external = update.Principal
	transitioned = update.LocallyDisabled
	if !update.StatusChanged || update.PreviousStatus == nil ||
		*update.PreviousStatus != principals.ExternalIdentityActive {
		t.Errorf("disabled observation change = %v previous %v, want true/active",
			update.StatusChanged, update.PreviousStatus)
	}
	if !transitioned || external.Status != principals.StatusDisabled ||
		external.ExternalIdentityStatus == nil ||
		*external.ExternalIdentityStatus != principals.ExternalIdentityDisabled ||
		external.ExternalIdentityStatusChangedAt == nil ||
		!external.ExternalIdentityStatusChangedAt.After(marker) {
		t.Errorf("external disabled result = transitioned %v principal %+v", transitioned, external)
	}

	update, err = store.RecordExternalIdentityStatus(
		ctx, pool, human.ID, principals.ExternalIdentityActive, false)
	if err != nil {
		t.Fatalf("record external re-enabled: %v", err)
	}
	external = update.Principal
	transitioned = update.LocallyDisabled
	if !update.StatusChanged || update.PreviousStatus == nil ||
		*update.PreviousStatus != principals.ExternalIdentityDisabled {
		t.Errorf("re-enabled observation change = %v previous %v, want true/disabled",
			update.StatusChanged, update.PreviousStatus)
	}
	if transitioned || external.Status != principals.StatusDisabled ||
		external.ExternalIdentityStatus == nil ||
		*external.ExternalIdentityStatus != principals.ExternalIdentityActive {
		t.Errorf("external re-enable must not auto-enable local principal: transitioned %v principal %+v",
			transitioned, external)
	}
}
