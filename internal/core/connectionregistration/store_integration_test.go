//go:build integration

package connectionregistration_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestStoreRegistrationReplayAliasesAndImmutableIntent(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := connectionregistration.NewStore()
	owner := connectionregistration.Owner{Type: "service", ID: uuid.New()}
	source, err := store.CreateSource(ctx, pool, connectionregistration.Source{ID: uuid.New(), Name: "fixture", Owner: owner, Environment: "test", TargetSpec: []byte(`{"engine":"postgres"}`)})
	if err != nil {
		t.Fatal(err)
	}
	source, err = store.FinalizeSource(ctx, pool, source.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	params := connectionregistration.ReserveParams{Owner: owner, RequestID: uuid.New(), RegistrationKey: "fixture:" + uuid.NewString(), Environment: "test", Spec: []byte(`{"engine":"postgres","tags":[]}`), CredentialSourceID: source.ID, CredentialSourceVersion: 1}
	reserve := func(p connectionregistration.ReserveParams) (connectionregistration.Registration, bool, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return connectionregistration.Registration{}, false, err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := store.LockOwner(ctx, tx, p.Owner); err != nil {
			return connectionregistration.Registration{}, false, err
		}
		r, created, err := store.Reserve(ctx, tx, p)
		if err != nil {
			return r, created, err
		}
		return r, created, tx.Commit(ctx)
	}
	first, created, err := reserve(params)
	if err != nil || !created {
		t.Fatalf("reserve created=%v err=%v", created, err)
	}
	replayed, created, err := reserve(params)
	if err != nil || created || replayed.ID != first.ID || replayed.ConnectionID != first.ConnectionID || replayed.OperationID != first.OperationID {
		t.Fatalf("replay mismatch created=%v err=%v", created, err)
	}
	alias := params
	alias.RequestID = uuid.New()
	alias.Spec = []byte(`{"tags": [], "engine": "postgres"}`)
	replayed, created, err = reserve(alias)
	if err != nil || created || replayed.ID != first.ID {
		t.Fatalf("alias mismatch created=%v err=%v", created, err)
	}
	conflict := alias
	conflict.RegistrationKey = "another-key"
	if _, _, err := reserve(conflict); !errors.Is(err, connectionregistration.ErrConflict) {
		t.Fatalf("alias request reuse err=%v", err)
	}
	conflict = params
	conflict.CredentialSourceVersion = 2
	if _, _, err := reserve(conflict); !errors.Is(err, connectionregistration.ErrConflict) {
		t.Fatalf("source version reuse err=%v", err)
	}
	if _, err := pool.Exec(ctx, `update connection_registrations set spec='{"changed":true}' where id=$1`, first.ID); err == nil {
		t.Fatal("immutable registration intent was changed")
	}
	if _, err := store.SetCanonicalVersion(ctx, pool, first.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginCancellation(ctx, pool, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishCancellation(ctx, pool, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `update connection_registrations set phase='registered' where id=$1`, first.ID); err == nil {
		t.Fatal("cancelled registration was reused")
	}
	other := params
	other.Owner.ID = uuid.New()
	otherReg, created, err := reserve(other)
	if err != nil || !created || otherReg.ID == first.ID {
		t.Fatalf("different owners share registration created=%v err=%v", created, err)
	}
}

func TestStoreConcurrentRegistrationUsesOneReservation(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := connectionregistration.NewStore()
	owner := connectionregistration.Owner{Type: "user", ID: uuid.New()}
	source, err := store.CreateSource(ctx, pool, connectionregistration.Source{ID: uuid.New(), Name: "concurrent", Owner: owner, Environment: "test", TargetSpec: []byte(`{"engine":"postgres"}`)})
	if err != nil {
		t.Fatal(err)
	}
	params := connectionregistration.ReserveParams{Owner: owner, RegistrationKey: "concurrent:" + uuid.NewString(), Environment: "test", Spec: []byte(`{"engine":"postgres"}`), CredentialSourceID: source.ID, CredentialSourceVersion: 1}
	type result struct {
		id      uuid.UUID
		created bool
		err     error
	}
	results := make(chan result, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if err := store.LockOwner(ctx, tx, owner); err != nil {
				results <- result{err: err}
				return
			}
			p := params
			p.RequestID = uuid.New()
			r, created, err := store.Reserve(ctx, tx, p)
			if err == nil {
				err = tx.Commit(ctx)
			}
			results <- result{id: r.ID, created: created, err: err}
		})
	}
	group.Wait()
	close(results)
	var id uuid.UUID
	createdCount := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if id == uuid.Nil {
			id = r.id
		}
		if r.id != id {
			t.Fatal("concurrent requests reserved different registrations")
		}
		if r.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created reservations=%d", createdCount)
	}
}
