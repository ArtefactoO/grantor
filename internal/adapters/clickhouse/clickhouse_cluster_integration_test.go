//go:build integration

// Live cluster тест ClickHouse adapter. Гейт двухступенчатый: сначала
// обычный GRANTOR_TEST_CLICKHOUSE_URL (иначе skip, как у всех
// integration-тестов пакета), затем GRANTOR_TEST_CLICKHOUSE_CLUSTER — его
// выставляет scripts/test-integration.sh только под GRANTOR_TEST_CLUSTERS=1,
// когда в config.d обоих узлов записано определение remote_servers
// grantor_cluster (целевой узел — локальная реплика, второй — удалённая).
// Это detection-level кластеризация: adapter определяет топологию по
// system.clusters, без Keeper и Replicated-таблиц (ON CLUSTER DDL — вне
// scope, см. limitations в docs). Без гейта тест пропускается, и прогон по
// умолчанию не замедляется.
package clickhouse_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
)

// clickhouseClusterEnv — маркер harness-а «целевой сервер — участник
// multi-host кластера grantor_cluster». Влияет и на standalone-тесты пакета:
// ожидаемая топология в TestDiscoverFixture становится cluster, а
// TestTopologyStandalone пропускается (см. wantClickhouseTopology).
const clickhouseClusterEnv = "GRANTOR_TEST_CLICKHOUSE_CLUSTER"

// harnessClusterName — имя кластера из remote_servers-определения harness-а.
const harnessClusterName = "grantor_cluster"

// clickhouseClustered сообщает, является ли целевой сервер участником
// multi-host кластера.
func clickhouseClustered() bool { return os.Getenv(clickhouseClusterEnv) != "" }

// wantClickhouseTopology возвращает топологию, которую discovery должен
// увидеть на целевом сервере в текущем режиме harness-а.
func wantClickhouseTopology() string {
	if clickhouseClustered() {
		return "cluster"
	}
	return "standalone"
}

// TestTopologyCluster проверяет определение топологии на живом multi-host
// кластере: ValidateConnection проходит, Discover возвращает cluster
// grantor_cluster с двумя хостами из system.clusters.
func TestTopologyCluster(t *testing.T) {
	rawURL, _, _, _ := target(t)
	if !clickhouseClustered() {
		t.Skipf("%s is not set; skipping ClickHouse live cluster test", clickhouseClusterEnv)
	}
	ctx := context.Background()
	ad := clickhouse.New()
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
	if snap.Topology["cluster_name"] != harnessClusterName {
		t.Errorf("cluster_name = %v, want %s", snap.Topology["cluster_name"], harnessClusterName)
	}
	clusters, ok := snap.Topology["clusters"].([]string)
	if !ok || !slices.Contains(clusters, harnessClusterName) {
		t.Errorf("clusters = %v, want it to contain %s", snap.Topology["clusters"], harnessClusterName)
	}
	if snap.Topology["host_count"] != 2 {
		t.Errorf("host_count = %v, want 2", snap.Topology["host_count"])
	}
	hosts, ok := snap.Topology["hosts"].([]string)
	if !ok || len(hosts) != 2 {
		t.Fatalf("hosts = %v, want a list of 2 hosts", snap.Topology["hosts"])
	}
	for _, h := range hosts {
		if h == "" {
			t.Errorf("hosts = %v, host addresses must be non-empty", hosts)
		}
	}
}
