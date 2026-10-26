package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
)

type fakeConnectorStore struct {
	sessions []connectorstate.Session
	within   time.Duration
	calls    int
	err      error
}

func (f *fakeConnectorStore) ExpiringSoon(
	_ context.Context, _ pgx.Tx, _ time.Time, within time.Duration,
) ([]connectorstate.Session, error) {
	f.calls++
	f.within = within
	return f.sessions, f.err
}

// Порог 0 — та же семантика, что у прочих порогов обслуживания: проверка
// выключена, а не «предупреждать обо всём».
func TestConnectorCertificatesDisabledByZeroThreshold(t *testing.T) {
	store := &fakeConnectorStore{sessions: []connectorstate.Session{{ConnectorID: "test"}}}
	r := &Runner{cfg: Config{}, connectors: store}

	count, err := r.evaluateConnectorCertificates(context.Background(), nil, time.Now())

	if err != nil {
		t.Fatalf("evaluateConnectorCertificates: %v", err)
	}
	if count != 0 || store.calls != 0 {
		t.Fatalf("count = %d, calls = %d, want 0 and 0", count, store.calls)
	}
}

// Control plane без gateway не должен считать отсутствие наблюдений
// проблемой: connector'ов просто нет.
func TestConnectorCertificatesSkippedWithoutStore(t *testing.T) {
	r := &Runner{cfg: Config{ConnectorCertificateWarning: time.Hour}}

	count, err := r.evaluateConnectorCertificates(context.Background(), nil, time.Now())

	if err != nil || count != 0 {
		t.Fatalf("count = %d, err = %v, want 0 and nil", count, err)
	}
}

func TestConnectorCertificatesCountsExpiring(t *testing.T) {
	now := time.Now()
	store := &fakeConnectorStore{sessions: []connectorstate.Session{
		{ConnectorID: "test", CertificateNotAfter: now.Add(24 * time.Hour)},
		{ConnectorID: "segment-b", CertificateNotAfter: now.Add(-time.Hour)},
	}}
	r := &Runner{cfg: Config{ConnectorCertificateWarning: 720 * time.Hour}, connectors: store}

	count, err := r.evaluateConnectorCertificates(context.Background(), nil, now)

	if err != nil {
		t.Fatalf("evaluateConnectorCertificates: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2 (истёкший тоже требует внимания)", count)
	}
	if store.within != 720*time.Hour {
		t.Fatalf("within = %s, want порог из конфигурации", store.within)
	}
}

// Сбой чтения наблюдений не должен выглядеть как «проблем нет».
func TestConnectorCertificatesPropagatesError(t *testing.T) {
	store := &fakeConnectorStore{err: errors.New("db is down")}
	r := &Runner{cfg: Config{ConnectorCertificateWarning: time.Hour}, connectors: store}

	if _, err := r.evaluateConnectorCertificates(context.Background(), nil, time.Now()); err == nil {
		t.Fatal("evaluateConnectorCertificates: want error, got nil")
	}
}
