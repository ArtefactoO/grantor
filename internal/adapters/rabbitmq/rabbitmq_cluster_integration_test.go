//go:build integration

// Live cluster тест RabbitMQ adapter. Гейт двухступенчатый: сначала обычный
// GRANTOR_TEST_RABBITMQ_URL (иначе skip, как у всех integration-тестов
// пакета), затем GRANTOR_TEST_RABBITMQ_CLUSTER — его выставляет
// scripts/test-integration.sh только под GRANTOR_TEST_CLUSTERS=1, когда к
// целевому узлу реально присоединён второй узел (join_cluster). Без гейта
// тест пропускается, и прогон по умолчанию не замедляется.
package rabbitmq_test

import (
	"context"
	"os"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
)

// rabbitClusterEnv — маркер harness-а «целевой RabbitMQ — двухузловой
// кластер». Влияет и на standalone-тесты пакета: ожидаемая топология в
// TestDiscoverFixture становится cluster, а TestTopologyStandalone
// пропускается (см. wantRabbitTopology).
const rabbitClusterEnv = "GRANTOR_TEST_RABBITMQ_CLUSTER"

// rabbitClustered сообщает, присоединён ли к целевому узлу второй узел.
func rabbitClustered() bool { return os.Getenv(rabbitClusterEnv) != "" }

// wantRabbitTopology возвращает топологию, которую discovery должен увидеть
// на целевом узле в текущем режиме harness-а.
func wantRabbitTopology() string {
	if rabbitClustered() {
		return "cluster"
	}
	return "standalone"
}

// TestTopologyCluster проверяет определение топологии на живом двухузловом
// кластере: ValidateConnection проходит, Discover возвращает cluster с двумя
// перечисленными узлами (/api/nodes с обоих сторон join).
func TestTopologyCluster(t *testing.T) {
	rawURL, _, _, _ := target(t)
	if !rabbitClustered() {
		t.Skipf("%s is not set; skipping RabbitMQ live cluster test", rabbitClusterEnv)
	}
	ctx := context.Background()
	ad := rabbitmq.New()
	conn := connectionFromURL(t, rawURL)

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
	if snap.Topology["node_count"] != 2 {
		t.Errorf("node_count = %v, want 2", snap.Topology["node_count"])
	}
	nodes, ok := snap.Topology["nodes"].([]string)
	if !ok || len(nodes) != 2 {
		t.Fatalf("nodes = %v, want a list of 2 node names", snap.Topology["nodes"])
	}
	for _, n := range nodes {
		if n == "" {
			t.Errorf("nodes = %v, node names must be non-empty", nodes)
		}
	}
}
