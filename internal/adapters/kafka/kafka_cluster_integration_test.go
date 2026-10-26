//go:build integration

// Live cluster тест Kafka adapter. Гейт двухступенчатый: сначала обычные
// GRANTOR_TEST_KAFKA_BROKER/USER/PASS (иначе skip, как у всех
// integration-тестов пакета), затем GRANTOR_TEST_KAFKA_CLUSTER — его
// выставляет scripts/test-integration.sh только под GRANTOR_TEST_CLUSTERS=1,
// когда к целевой Redpanda реально присоединён второй брокер (--seeds).
// Без гейта тест пропускается, и прогон по умолчанию не замедляется.
package kafka_test

import (
	"context"
	"os"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
)

// kafkaClusterEnv — маркер harness-а «целевой брокер — двухброкерный
// кластер». Влияет и на standalone-тесты пакета: ожидаемая топология в
// TestDiscoverFixture становится cluster, а TestTopologyStandalone
// пропускается (см. wantKafkaTopology).
const kafkaClusterEnv = "GRANTOR_TEST_KAFKA_CLUSTER"

// kafkaClustered сообщает, присоединён ли к целевому брокеру второй брокер.
func kafkaClustered() bool { return os.Getenv(kafkaClusterEnv) != "" }

// wantKafkaTopology возвращает топологию, которую discovery должен увидеть
// на целевом брокере в текущем режиме harness-а.
func wantKafkaTopology() string {
	if kafkaClustered() {
		return "cluster"
	}
	return "standalone"
}

// TestTopologyCluster проверяет определение топологии на живом двухброкерном
// кластере: ValidateConnection проходит, Discover возвращает cluster с двумя
// брокерами в Metadata.
func TestTopologyCluster(t *testing.T) {
	broker, user, pass := target(t)
	if !kafkaClustered() {
		t.Skipf("%s is not set; skipping Kafka live cluster test", kafkaClusterEnv)
	}
	ctx := context.Background()
	ad := kafka.New()
	conn := connection(broker, user, pass)

	if err := ad.ValidateConnection(ctx, conn); err != nil {
		t.Fatalf("ValidateConnection against cluster: %v", err)
	}
	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "cluster" {
		t.Errorf("topology = %v, want cluster", snap.Topology["topology"])
	}
	if snap.Topology["broker_count"] != 2 {
		t.Errorf("broker_count = %v, want 2", snap.Topology["broker_count"])
	}
	brokers, ok := snap.Topology["brokers"].([]string)
	if !ok || len(brokers) != 2 {
		t.Fatalf("brokers = %v, want a list of 2 broker addresses", snap.Topology["brokers"])
	}
	for _, b := range brokers {
		if b == "" {
			t.Errorf("brokers = %v, broker addresses must be non-empty", brokers)
		}
	}
}
