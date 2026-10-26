package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
)

// Реестр adapters — глобальный и запрещает повторную регистрацию, поэтому
// движки заводятся один раз на пакет.
func TestMain(m *testing.M) {
	adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	adapter.Register(rabbitmq.Engine, func() adapter.Adapter { return rabbitmq.New() })
	os.Exit(m.Run())
}

// Gateway маршрутизирует задание connector'у только по объявленным в Hello
// capabilities. Пока их брали у одного движка, connector с несколькими
// зарегистрированными adapters молча не получал заданий для остальных.
func TestRegisteredCapabilitiesCoversEveryEngine(t *testing.T) {
	caps := registeredCapabilities()

	for _, engine := range []struct {
		name     string
		manifest adapter.Manifest
	}{
		{postgres.Engine, postgres.New().Manifest()},
		{rabbitmq.Engine, rabbitmq.New().Manifest()},
	} {
		for _, want := range engine.manifest.Capabilities {
			if !slices.Contains(caps, want) {
				t.Errorf("capability %q of %s is not announced", want, engine.name)
			}
		}
	}
}

// Движки делят общие capabilities (discover, account.create); дубликаты в
// Hello — мусор в протоколе.
func TestRegisteredCapabilitiesHasNoDuplicates(t *testing.T) {
	caps := registeredCapabilities()

	seen := make(map[adapter.Capability]bool, len(caps))
	for _, c := range caps {
		if seen[c] {
			t.Fatalf("capability %q announced twice", c)
		}
		seen[c] = true
	}
}

// Phase 3 connector advertises the complete local v2 adapter contract. The
// gateway checks this exact marker on the active Hello before wire delivery.
func TestRegisteredCapabilitiesAdvertisesPostgresSuperuserDirectV1(t *testing.T) {
	if caps := registeredCapabilities(); !slices.Contains(caps, adapter.CapPostgresSuperuserDirectV1) {
		t.Fatalf("registered/Hello capabilities do not contain %q", adapter.CapPostgresSuperuserDirectV1)
	}
}

func TestRegisteredCapabilitiesAdvertisesPinnedStatsMembership(t *testing.T) {
	if caps := registeredCapabilities(); !slices.Contains(caps, adapter.CapPostgresStatsMembershipV1) {
		t.Fatal("connector cannot negotiate the pinned statistics contract")
	}
}

// Разрыв связи с gateway — штатное событие, а не отказ конфигурации: выход
// из процесса перекладывал восстановление на рестарты пода.
func TestRunWithReconnectRetriesUntilContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := runWithReconnect(ctx, func(context.Context) error {
		attempts++
		if attempts == 3 {
			cancel()
		}
		return errors.New("connection reset")
	})

	if err != nil {
		t.Fatalf("runWithReconnect returned %v, want nil after cancel", err)
	}
	if attempts < 3 {
		t.Fatalf("attempts = %d, want at least 3", attempts)
	}
}

// Остановка по сигналу не должна выглядеть как сбой соединения.
func TestRunWithReconnectStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runWithReconnect(ctx, func(context.Context) error {
		return errors.New("connection reset")
	}); err != nil {
		t.Fatalf("runWithReconnect returned %v, want nil", err)
	}
}
