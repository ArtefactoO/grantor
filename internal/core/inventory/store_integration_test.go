//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// newTestConnection создаёт подключение-носитель инвентаря: все проверки
// теста скоупятся его id, поэтому тесты не мешают друг другу в общей
// базе.
func newTestConnection(ctx context.Context, t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-inventory-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return conn
}

// fullSnapshot строит снапшот с иерархией ресурсов, двумя аккаунтами,
// permission и binding svc -> role:readers.
func fullSnapshot() *adapter.Snapshot {
	return &adapter.Snapshot{
		ServerVersion: "16.4",
		Resources: []adapter.ObservedResource{
			{
				Kind:          "database",
				ExternalID:    "db:app",
				Name:          "app",
				CanonicalPath: "app",
				Attributes:    map[string]any{"owner": "postgres"},
				Fingerprint:   "fp-db-1",
			},
			{
				Kind:             "schema",
				ExternalID:       "schema:app.public",
				ParentExternalID: "db:app",
				Name:             "public",
				CanonicalPath:    "app.public",
				Attributes:       map[string]any{"owner": "postgres"},
				Fingerprint:      "fp-schema-1",
			},
		},
		Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "svc", Attributes: map[string]any{"can_login": true}},
			{Kind: "group", EngineIdentity: "readers", Attributes: map[string]any{"can_login": false}},
		},
		Permissions: []adapter.ObservedPermission{
			{ExternalID: "role:readers", Name: "readers", Assignable: true},
		},
		Bindings: []adapter.ObservedBinding{
			{AccountEngineIdentity: "svc", PermissionExternalID: "role:readers"},
		},
		ObservedAt: time.Now(),
	}
}

// resourceByExternalID находит ресурс в списке по external id.
func resourceByExternalID(t *testing.T, resources []inventory.Resource, externalID string) inventory.Resource {
	t.Helper()
	for _, r := range resources {
		if r.ExternalID == externalID {
			return r
		}
	}
	t.Fatalf("resource %q not found", externalID)
	return inventory.Resource{}
}

func TestUpsertSnapshotIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, fullSnapshot(), time.Now())
	if err != nil {
		t.Fatalf("first UpsertSnapshot: %v", err)
	}
	want := inventory.UpsertStats{Resources: 2, Accounts: 2, Permissions: 1, Bindings: 1}
	if stats != want {
		t.Errorf("first UpsertSnapshot stats = %+v, want %+v", stats, want)
	}

	firstResources, err := store.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(firstResources) != 2 {
		t.Fatalf("resources after first upsert = %d, want 2", len(firstResources))
	}
	db := resourceByExternalID(t, firstResources, "db:app")
	schema := resourceByExternalID(t, firstResources, "schema:app.public")
	if schema.ParentID == nil || *schema.ParentID != db.ID {
		t.Errorf("schema parent = %v, want %s", schema.ParentID, db.ID)
	}
	if db.ParentID != nil {
		t.Errorf("database parent = %v, want nil", db.ParentID)
	}
	if db.Status != "observed" || schema.Status != "observed" {
		t.Errorf("statuses = %q/%q, want observed/observed", db.Status, schema.Status)
	}

	firstBindings, err := store.ListBindingsByAccount(ctx, pool, accountID(ctx, t, pool, store, conn.ID, "svc"))
	if err != nil {
		t.Fatalf("ListBindingsByAccount: %v", err)
	}
	if len(firstBindings) != 1 {
		t.Fatalf("bindings after first upsert = %d, want 1", len(firstBindings))
	}
	fb := firstBindings[0]
	if fb.Source != "external" || fb.DesiredState != nil ||
		fb.ObservedState != inventory.BindingPresent || fb.Status != inventory.BindingStatusObserved {
		t.Errorf("first binding = %+v, want external/unmanaged/present/observed", fb)
	}

	// Повторное сведение того же снапшота: updated_at не меняется,
	// observed_at бампается.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, fullSnapshot(), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("second UpsertSnapshot: %v", err)
	}
	secondResources, err := store.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListResources after second upsert: %v", err)
	}
	for _, first := range firstResources {
		second := resourceByExternalID(t, secondResources, first.ExternalID)
		if !second.UpdatedAt.Equal(first.UpdatedAt) {
			t.Errorf("resource %q updated_at changed on identical snapshot: %v -> %v",
				first.ExternalID, first.UpdatedAt, second.UpdatedAt)
		}
		if second.ObservedAt == nil || first.ObservedAt == nil || !second.ObservedAt.After(*first.ObservedAt) {
			t.Errorf("resource %q observed_at not bumped: %v -> %v",
				first.ExternalID, first.ObservedAt, second.ObservedAt)
		}
	}
	secondBindings, err := store.ListBindingsByAccount(ctx, pool, fb.AccountID)
	if err != nil {
		t.Fatalf("ListBindingsByAccount after second upsert: %v", err)
	}
	if len(secondBindings) != 1 {
		t.Fatalf("bindings after second upsert = %d, want 1", len(secondBindings))
	}
	if !secondBindings[0].UpdatedAt.Equal(fb.UpdatedAt) {
		t.Errorf("binding updated_at changed on identical snapshot: %v -> %v",
			fb.UpdatedAt, secondBindings[0].UpdatedAt)
	}

	// Изменившийся fingerprint перезаписывает содержимое и updated_at.
	changed := fullSnapshot()
	changed.Resources[0].Attributes = map[string]any{"owner": "new_owner"}
	changed.Resources[0].Fingerprint = "fp-db-2"
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, changed, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("third UpsertSnapshot: %v", err)
	}
	thirdResources, err := store.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListResources after third upsert: %v", err)
	}
	dbThird := resourceByExternalID(t, thirdResources, "db:app")
	if dbThird.Fingerprint != "fp-db-2" {
		t.Errorf("db fingerprint = %q, want fp-db-2", dbThird.Fingerprint)
	}
	if !dbThird.UpdatedAt.After(db.UpdatedAt) {
		t.Errorf("db updated_at not bumped on fingerprint change: %v -> %v", db.UpdatedAt, dbThird.UpdatedAt)
	}
}

// accountID возвращает id аккаунта connection по engine identity.
func accountID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *inventory.Store, connectionID uuid.UUID, identity string) uuid.UUID {
	t.Helper()
	accounts, err := store.ListAccounts(ctx, pool, connectionID)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	for _, a := range accounts {
		if a.EngineIdentity == identity {
			return a.ID
		}
	}
	t.Fatalf("account %q not found", identity)
	return uuid.Nil
}

func TestUpsertSnapshotMissingAndDrift(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, fullSnapshot(), time.Now()); err != nil {
		t.Fatalf("initial UpsertSnapshot: %v", err)
	}
	svcID := accountID(ctx, t, pool, store, conn.ID, "svc")

	// Снапшот без схемы и без binding: ресурс -> missing, binding ->
	// observed absent; статус непринятого binding — observed (применять его
	// никто не собирается).
	reduced := fullSnapshot()
	reduced.Resources = reduced.Resources[:1]
	reduced.Bindings = nil
	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, reduced, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("reduced UpsertSnapshot: %v", err)
	}
	if stats.MissingResources != 1 {
		t.Errorf("missing resources = %d, want 1", stats.MissingResources)
	}
	resources, err := store.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if got := resourceByExternalID(t, resources, "schema:app.public").Status; got != "missing" {
		t.Errorf("schema status = %q, want missing", got)
	}
	bindings, err := store.ListBindingsByAccount(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("ListBindingsByAccount: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	if bindings[0].ObservedState != inventory.BindingAbsent {
		t.Errorf("binding observed = %q, want absent", bindings[0].ObservedState)
	}
	if bindings[0].Status != inventory.BindingStatusObserved {
		t.Errorf("unmanaged absent binding status = %q, want observed", bindings[0].Status)
	}

	// Возврат ресурса и binding в снапшот: missing -> observed.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, fullSnapshot(), time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("restore UpsertSnapshot: %v", err)
	}
	resources, err = store.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListResources after restore: %v", err)
	}
	if got := resourceByExternalID(t, resources, "schema:app.public").Status; got != "observed" {
		t.Errorf("restored schema status = %q, want observed", got)
	}

	// Managed binding: desired_state='present' задаётся вручную (adopt);
	// присутствие в снапшоте даёт synced, исчезновение — drift.
	if _, err := pool.Exec(ctx,
		`update bindings set desired_state = 'present' where account_id = $1`, svcID); err != nil {
		t.Fatalf("adopt binding: %v", err)
	}
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, fullSnapshot(), time.Now().Add(3*time.Minute)); err != nil {
		t.Fatalf("managed present UpsertSnapshot: %v", err)
	}
	bindings, err = store.ListBindingsByAccount(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("ListBindingsByAccount: %v", err)
	}
	if bindings[0].Status != inventory.BindingStatusSynced {
		t.Errorf("managed present binding status = %q, want synced", bindings[0].Status)
	}

	reduced = fullSnapshot()
	reduced.Bindings = nil
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, reduced, time.Now().Add(4*time.Minute)); err != nil {
		t.Fatalf("managed absent UpsertSnapshot: %v", err)
	}
	bindings, err = store.ListBindingsByAccount(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("ListBindingsByAccount: %v", err)
	}
	if bindings[0].ObservedState != inventory.BindingAbsent || bindings[0].Status != inventory.BindingStatusDrift {
		t.Errorf("managed absent binding = %q/%q, want absent/drift",
			bindings[0].ObservedState, bindings[0].Status)
	}
}

func TestDriftSummary(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	// Два binding: svc остаётся unmanaged, readers становится managed.
	snap := fullSnapshot()
	snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
		AccountEngineIdentity: "readers",
		PermissionExternalID:  "role:readers",
	})
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("initial UpsertSnapshot: %v", err)
	}

	readersID := accountID(ctx, t, pool, store, conn.ID, "readers")
	if _, err := pool.Exec(ctx,
		`update bindings set desired_state = 'present', source = 'service' where account_id = $1`,
		readersID); err != nil {
		t.Fatalf("adopt readers binding: %v", err)
	}
	// Managed схема, которая исчезнет из снапшота.
	if _, err := pool.Exec(ctx,
		`update resources set ownership = 'managed'
		 where connection_id = $1 and external_id = 'schema:app.public'`, conn.ID); err != nil {
		t.Fatalf("mark schema managed: %v", err)
	}

	// Снапшот без схемы и без binding readers: managed ресурс missing,
	// managed binding drift, unmanaged binding svc остаётся unmanaged.
	reduced := fullSnapshot()
	reduced.Resources = reduced.Resources[:1]
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, reduced, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reduced UpsertSnapshot: %v", err)
	}

	drift, err := store.DriftSummary(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("DriftSummary: %v", err)
	}
	want := inventory.DriftCounters{
		UnmanagedBindings:       1,
		DriftBindings:           1,
		MissingManagedResources: 1,
	}
	if drift != want {
		t.Errorf("DriftSummary = %+v, want %+v", drift, want)
	}

	// Read-методы: смоук поверх сведённого инвентаря.
	db := resourceByExternalID(t, mustListResources(ctx, t, pool, store, conn.ID), "db:app")
	got, err := store.GetResource(ctx, pool, db.ID)
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if got.ExternalID != "db:app" {
		t.Errorf("GetResource external id = %q, want db:app", got.ExternalID)
	}
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(permissions) != 1 || permissions[0].ExternalID != "role:readers" {
		t.Errorf("ListPermissions = %+v, want single role:readers", permissions)
	}
	byResource, err := store.ListBindingsByResource(ctx, pool, db.ID)
	if err != nil {
		t.Fatalf("ListBindingsByResource: %v", err)
	}
	if len(byResource) != 0 {
		t.Errorf("ListBindingsByResource = %d bindings, want 0 (cluster-wide bindings)", len(byResource))
	}
}

// Failed binding — то же доказанное расхождение, что и drift: до этой
// выборки провал применения не был виден ни в findings, ни в счётчиках.
func TestDriftIncludesFailedBinding(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	snap := fullSnapshot()
	snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
		AccountEngineIdentity: "readers",
		PermissionExternalID:  "role:readers",
	})
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("UpsertSnapshot: %v", err)
	}
	readersID := accountID(ctx, t, pool, store, conn.ID, "readers")
	if _, err := pool.Exec(ctx,
		`update bindings set desired_state = 'present', source = 'service' where account_id = $1`,
		readersID); err != nil {
		t.Fatalf("adopt readers binding: %v", err)
	}
	var bindingID uuid.UUID
	if err := pool.QueryRow(ctx,
		`select id from bindings where account_id = $1`, readersID).Scan(&bindingID); err != nil {
		t.Fatalf("read binding id: %v", err)
	}
	if err := store.MarkBindingFailed(ctx, pool, bindingID); err != nil {
		t.Fatalf("MarkBindingFailed: %v", err)
	}

	drift, err := store.DriftSummary(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("DriftSummary: %v", err)
	}
	if drift.DriftBindings != 1 {
		t.Errorf("DriftSummary.DriftBindings = %d, want 1 (failed counts)", drift.DriftBindings)
	}

	findings, err := store.DriftFindings(ctx, pool, &conn.ID)
	if err != nil {
		t.Fatalf("DriftFindings: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Kind == inventory.DriftKindBindingDrift && f.BindingID != nil && *f.BindingID == bindingID {
			found = true
		}
	}
	if !found {
		t.Errorf("failed binding %s not present in drift findings: %+v", bindingID, findings)
	}
}

// mustListResources возвращает ресурсы connection или валит тест.
func mustListResources(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *inventory.Store, connectionID uuid.UUID) []inventory.Resource {
	t.Helper()
	resources, err := store.ListResources(ctx, pool, connectionID)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	return resources
}

// TestAdoptAccountBindingsAndSetManaged проверяет adopt-методы store:
// массовое принятие unmanaged bindings одним UPDATE (managed bindings не
// трогаются, повтор идемпотентен), счётчик dangerous unmanaged bindings и
// перевод аккаунта в managed с дозаполнением vault_path/credential_mode.
func TestAdoptAccountBindingsAndSetManaged(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	// Снапшот: svc несёт unmanaged bindings на role:readers и dangerous
	// role:admin; readers — managed binding (desired задаётся ниже).
	snap := fullSnapshot()
	snap.Permissions = append(snap.Permissions, adapter.ObservedPermission{
		ExternalID: "role:admin", Name: "admin", Assignable: true, Dangerous: true,
	})
	snap.Bindings = append(snap.Bindings,
		adapter.ObservedBinding{AccountEngineIdentity: "svc", PermissionExternalID: "role:admin"},
		adapter.ObservedBinding{AccountEngineIdentity: "readers", PermissionExternalID: "role:readers"},
	)
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("UpsertSnapshot: %v", err)
	}
	svcID := accountID(ctx, t, pool, store, conn.ID, "svc")
	readersID := accountID(ctx, t, pool, store, conn.ID, "readers")
	if _, err := pool.Exec(ctx,
		`update bindings set desired_state = 'present', source = 'service' where account_id = $1`,
		readersID); err != nil {
		t.Fatalf("mark readers binding managed: %v", err)
	}

	dangerous, err := store.CountUnmanagedDangerousBindings(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("CountUnmanagedDangerousBindings: %v", err)
	}
	if dangerous != 1 {
		t.Errorf("dangerous unmanaged bindings = %d, want 1", dangerous)
	}
	if n, err := store.CountUnmanagedDangerousBindings(ctx, pool, readersID); err != nil || n != 0 {
		t.Errorf("readers dangerous count = %d (err=%v), want 0", n, err)
	}

	adopted, err := store.AdoptAccountBindings(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("AdoptAccountBindings: %v", err)
	}
	if adopted != 2 {
		t.Errorf("adopted bindings = %d, want 2", adopted)
	}
	bindings, err := store.ListBindingsByAccount(ctx, pool, svcID)
	if err != nil {
		t.Fatalf("ListBindingsByAccount: %v", err)
	}
	for _, b := range bindings {
		if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			t.Errorf("binding %s desired = %v, want present", b.ID, b.DesiredState)
		}
		// Observed из discovery — present, значит adopt даёт synced
		// (эквивалент ResolveBindingStatus).
		if b.Status != inventory.BindingStatusSynced {
			t.Errorf("binding %s status = %q, want synced", b.ID, b.Status)
		}
		if b.Source != "external" {
			t.Errorf("binding %s source = %q, want external (unchanged)", b.ID, b.Source)
		}
	}

	// Повтор — 0 строк без ошибки; managed binding readers не тронут.
	if n, err := store.AdoptAccountBindings(ctx, pool, svcID); err != nil || n != 0 {
		t.Errorf("repeated AdoptAccountBindings = %d (err=%v), want 0", n, err)
	}
	if n, err := store.CountUnmanagedDangerousBindings(ctx, pool, svcID); err != nil || n != 0 {
		t.Errorf("dangerous count after adopt = %d (err=%v), want 0", n, err)
	}

	// SetAccountManaged: metadata-режим (пустые path/mode) меняет только
	// ownership; повтор с path/mode дозаполняет их, не затирая ownership.
	updated, err := store.SetAccountManaged(ctx, pool, svcID, "", "")
	if err != nil {
		t.Fatalf("SetAccountManaged metadata: %v", err)
	}
	if updated.Ownership != inventory.OwnershipManaged {
		t.Errorf("ownership = %q, want managed", updated.Ownership)
	}
	if updated.VaultPath != "" || updated.CredentialMode != nil {
		t.Errorf("vault_path/credential_mode = %q/%v, want empty (metadata adopt)",
			updated.VaultPath, updated.CredentialMode)
	}
	path := "accounts/" + svcID.String() + "/credential"
	updated, err = store.SetAccountManaged(ctx, pool, svcID, path, inventory.CredentialModeProvided)
	if err != nil {
		t.Fatalf("SetAccountManaged with credential: %v", err)
	}
	if updated.VaultPath != path {
		t.Errorf("vault_path = %q, want %q", updated.VaultPath, path)
	}
	if updated.CredentialMode == nil || *updated.CredentialMode != inventory.CredentialModeProvided {
		t.Errorf("credential_mode = %v, want provided", updated.CredentialMode)
	}
	// Пустые аргументы не затирают уже заполненные колонки.
	updated, err = store.SetAccountManaged(ctx, pool, svcID, "", "")
	if err != nil {
		t.Fatalf("SetAccountManaged repeat: %v", err)
	}
	if updated.VaultPath != path || updated.CredentialMode == nil {
		t.Errorf("repeat cleared vault_path/credential_mode: %q/%v", updated.VaultPath, updated.CredentialMode)
	}

	if _, err := store.SetAccountManaged(ctx, pool, uuid.New(), "", ""); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("SetAccountManaged unknown id error = %v, want ErrNotFound", err)
	}
}

// TestLinkAccountPrincipalDetachesForeignCredential проверяет SQL-правило
// сброса указателя на общий секрет принципала. Правило продублировано в
// inventory.CredentialPointerForeign (юнит-тест account_guards_test.go);
// здесь фиксируется, что UPDATE ведёт себя так же — иначе две «версии
// истины» разъедутся молча.
func TestLinkAccountPrincipalDetachesForeignCredential(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	prStore := principals.NewStore()

	newPrincipal := func(name string) principals.Principal {
		p, err := prStore.Create(ctx, pool, principals.CreateParams{
			Type: principals.TypeService, DisplayName: name + " " + uuid.NewString()[:8],
		})
		if err != nil {
			t.Fatalf("create principal: %v", err)
		}
		return p
	}
	owner, other := newPrincipal("owner"), newPrincipal("other")
	sharedOf := func(p principals.Principal) string {
		path, err := vault.PrincipalEnvironmentCredentialPath(p.ID.String(), "prod")
		if err != nil {
			t.Fatalf("principal credential path: %v", err)
		}
		return path
	}
	newAccount := func(principalID *uuid.UUID, mode, path string) inventory.Account {
		a, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
			ConnectionID:   conn.ID,
			EngineIdentity: "itest_lnk_" + uuid.NewString()[:8],
			PrincipalID:    principalID,
			CredentialMode: mode,
			VaultPath:      path,
		})
		if err != nil {
			t.Fatalf("create managed account: %v", err)
		}
		return a
	}

	// Отвязка снимает указатель на общий секрет прежнего принципала.
	shared := newAccount(&owner.ID, inventory.CredentialModeExistingVaultRef, sharedOf(owner))
	unlinked, err := store.LinkAccountPrincipal(ctx, pool, shared.ID, nil)
	if err != nil {
		t.Fatalf("unlink shared account: %v", err)
	}
	if unlinked.PrincipalID != nil || unlinked.VaultPath != "" || unlinked.CredentialMode != nil {
		t.Errorf("after unlink = principal %v, path %q, mode %v; want fully detached",
			unlinked.PrincipalID, unlinked.VaultPath, unlinked.CredentialMode)
	}

	// Перепривязка на другого принципала — тот же сброс.
	moved := newAccount(&owner.ID, inventory.CredentialModeExistingVaultRef, sharedOf(owner))
	relinked, err := store.LinkAccountPrincipal(ctx, pool, moved.ID, &other.ID)
	if err != nil {
		t.Fatalf("relink shared account: %v", err)
	}
	if relinked.PrincipalID == nil || *relinked.PrincipalID != other.ID {
		t.Fatalf("relinked principal = %v, want %s", relinked.PrincipalID, other.ID)
	}
	if relinked.VaultPath != "" || relinked.CredentialMode != nil {
		t.Errorf("after relink = %q/%v, want detached", relinked.VaultPath, relinked.CredentialMode)
	}

	// Идемпотентная привязка к ТОМУ ЖЕ принципалу указатель не трогает.
	same := newAccount(&owner.ID, inventory.CredentialModeExistingVaultRef, sharedOf(owner))
	kept, err := store.LinkAccountPrincipal(ctx, pool, same.ID, &owner.ID)
	if err != nil {
		t.Fatalf("relink to the same principal: %v", err)
	}
	if kept.VaultPath != sharedOf(owner) || kept.CredentialMode == nil {
		t.Errorf("same-principal link changed credential: %q/%v", kept.VaultPath, kept.CredentialMode)
	}

	// Собственный путь аккаунта переживает отвязку: он ни на какого
	// принципала не ссылается, и терять его нельзя.
	own := newAccount(&owner.ID, inventory.CredentialModeGenerated, "accounts/"+uuid.NewString()+"/credential")
	detached, err := store.LinkAccountPrincipal(ctx, pool, own.ID, nil)
	if err != nil {
		t.Fatalf("unlink account with its own credential: %v", err)
	}
	if detached.VaultPath != own.VaultPath || detached.CredentialMode == nil ||
		*detached.CredentialMode != inventory.CredentialModeGenerated {
		t.Errorf("own credential lost on unlink: %q/%v", detached.VaultPath, detached.CredentialMode)
	}
}

func TestAccountLifecycleReservationAndRestoreGuards(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	opStore := operations.NewStore()
	conn := newTestConnection(ctx, t, pool)
	account, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "restore_" + uuid.NewString(),
		CredentialMode: inventory.CredentialModeProvided,
		VaultPath:      "accounts/old/credential",
	})
	if err != nil {
		t.Fatalf("CreateManagedAccount: %v", err)
	}

	// Первая транзакция держит account row lock до атомарного создания
	// operation. Конкурентный reserve обязан дождаться commit и увидеть
	// pending operation, а не зарезервировать второе поколение.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin first reserve: %v", err)
	}
	reserved, err := store.ReserveAccountLifecycle(ctx, tx, account.ID, inventory.AccountActive)
	if err != nil {
		t.Fatalf("ReserveAccountLifecycle first: %v", err)
	}
	if reserved.LifecycleVersion != 1 {
		t.Fatalf("first lifecycle version = %d, want 1", reserved.LifecycleVersion)
	}
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: "account.delete", ConnectionID: &conn.ID, AccountID: &account.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create lifecycle operation: %v", err)
	}

	secondDone := make(chan error, 1)
	go func() {
		secondTx, beginErr := pool.Begin(ctx)
		if beginErr != nil {
			secondDone <- beginErr
			return
		}
		defer secondTx.Rollback(ctx) //nolint:errcheck
		_, reserveErr := store.ReserveAccountLifecycle(ctx, secondTx, account.ID, inventory.AccountActive)
		secondDone <- reserveErr
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("concurrent reserve returned before row-lock owner committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit first reserve: %v", err)
	}
	select {
	case err := <-secondDone:
		if !errors.Is(err, inventory.ErrAccountLifecycleBusy) {
			t.Fatalf("concurrent reserve error = %v, want ErrAccountLifecycleBusy", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent reserve did not finish after first commit")
	}

	// Завершаем delete metadata, сохраняя tombstone и очищая bindings.
	deleteTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin delete metadata: %v", err)
	}
	if err := store.MarkAccountDeletedGuarded(ctx, deleteTx, account.ID,
		inventory.AccountActive, 1, "operator", "restore test"); err != nil {
		t.Fatalf("MarkAccountDeletedGuarded: %v", err)
	}
	if _, err := deleteTx.Exec(ctx,
		`update operations set status = 'success', finished_at = now() where id = $1`, op.ID); err != nil {
		t.Fatalf("finish delete operation: %v", err)
	}
	if err := deleteTx.Commit(ctx); err != nil {
		t.Fatalf("commit delete metadata: %v", err)
	}

	restoreTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin restore reserve: %v", err)
	}
	restoreReservation, err := store.ReserveAccountLifecycle(ctx, restoreTx, account.ID, inventory.AccountDeleted)
	if err != nil {
		t.Fatalf("reserve restore lifecycle: %v", err)
	}
	if restoreReservation.LifecycleVersion != 2 {
		t.Fatalf("restore lifecycle version = %d, want 2", restoreReservation.LifecycleVersion)
	}
	if err := restoreTx.Commit(ctx); err != nil {
		t.Fatalf("commit restore reserve: %v", err)
	}

	// Observed binding evidence blocks activation even for the correct
	// generation. After evidence is removed, restore reuses the same ID and
	// clears all deletion metadata.
	var permissionID uuid.UUID
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions (connection_id, engine, external_id, name)
		values ($1, 'postgres', $2, 'restore-test') returning id`,
		conn.ID, "restore-test-"+uuid.NewString()).Scan(&permissionID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		insert into bindings (account_id, permission_definition_id, source)
		values ($1, $2, 'external')`, account.ID, permissionID); err != nil {
		t.Fatalf("insert observed binding evidence: %v", err)
	}
	if _, err := store.RestoreAccountGuarded(ctx, pool, account.ID, 2,
		inventory.CredentialModeGenerated, "accounts/new/credential"); !errors.Is(err, inventory.ErrAccountStatusConflict) {
		t.Fatalf("restore with binding evidence error = %v, want ErrAccountStatusConflict", err)
	}
	if _, err := pool.Exec(ctx, `delete from bindings where account_id = $1`, account.ID); err != nil {
		t.Fatalf("delete observed binding evidence: %v", err)
	}
	restored, err := store.RestoreAccountGuarded(ctx, pool, account.ID, 2,
		inventory.CredentialModeGenerated, "accounts/new/credential")
	if err != nil {
		t.Fatalf("RestoreAccountGuarded: %v", err)
	}
	if restored.ID != account.ID || restored.Status != inventory.AccountActive ||
		restored.LifecycleVersion != 2 || restored.DeletedAt != nil ||
		restored.DeletedBy != nil || restored.DeleteReason != nil || restored.PrincipalID != nil {
		t.Errorf("restored account = %+v, want same id active lifecycle=2 and cleared tombstone", restored)
	}
	if restored.CredentialMode == nil || *restored.CredentialMode != inventory.CredentialModeGenerated ||
		restored.VaultPath != "accounts/new/credential" {
		t.Errorf("restored credential metadata = %v/%q", restored.CredentialMode, restored.VaultPath)
	}
	if err := inventory.CheckAccountLifecycle(restored, inventory.AccountActive, 1); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
		t.Fatalf("stale generation after restore error = %v, want ErrAccountLifecycleConflict", err)
	}
}
