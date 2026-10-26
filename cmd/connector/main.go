// Command grantor-connector — execution connector для сетевых зон без прямой
// связности control plane с целевой системой (docs/architecture.md, разделы
// 4.3 и 24; ADR-0002, ADR-0006, ADR-0014).
//
// Connector устанавливает ИСХОДЯЩЕЕ mTLS-соединение к gateway (внутри
// закрытой сети ничего не слушает), объявляет версию протокола и adapter
// capabilities (Hello) и исполняет присылаемые подписанные задания. С этапа 3
// поддержаны все виды заданий: discover, plan/apply/verify мутаций
// (grant/revoke, lifecycle managed-аккаунтов) и rotate_credential; connector
// шлёт heartbeat-кадры, по которым gateway отличает живой connector от
// умершего. Доступа к Vault у connector НЕТ (ADR-0014): credentials целевой
// системы резолвит control plane и доставляет отдельным кадром
// TypeCredentials по той же mTLS-сессии (в подписанных заданиях и
// результатах секретов нет); операции исполняются теми же engine adapters,
// что и у direct worker.
//
// # Транспорт
//
// stdlib crypto/tls + length-prefixed фрейминг Envelope (пакет
// internal/connector/wire). ConnectRPC — целевой транспорт (ADR-0002).
//
// # Окружение
//
//   - GRANTOR_CONNECTOR_ID — идентификатор connector (Hello.ConnectorID), по
//     умолчанию hostname.
//   - GRANTOR_CONNECTOR_GATEWAY_ADDR — адрес gateway host:port. Обязателен.
//   - GRANTOR_CONNECTOR_GATEWAY_SERVER_NAME — ожидаемый SNI/SAN сертификата
//     gateway; по умолчанию host из GRANTOR_CONNECTOR_GATEWAY_ADDR.
//   - GRANTOR_CONNECTOR_TLS_CERT / _TLS_KEY — PEM клиентского сертификата и
//     ключа connector (идентичность mTLS). Обязательны.
//   - GRANTOR_CONNECTOR_CA — PEM CA для проверки сертификата gateway.
//     Обязателен.
//   - GRANTOR_CONNECTOR_VERIFY_KEY — PEM Ed25519 публичного ключа (PKIX),
//     которым проверяются подписи заданий gateway. Обязателен.
//   - GRANTOR_CONNECTOR_KEY_ID — KeyID подписи заданий, по умолчанию "gateway".
//   - GRANTOR_CONNECTOR_DEPLOYMENT — среда развёртывания ("kubernetes", "vm",
//     "other") для подписи в UI; по умолчанию определяется автоматически.
//     Значение ни на что, кроме отображения, не влияет.
//
// Переменные Vault connector'у не нужны: credentials приходят от control
// plane (ADR-0014).
//
// Флаг -version печатает версию протокола и завершается кодом 0.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
	"github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
	"github.com/ArtefactoO/grantor/internal/serverutil"
)

func main() {
	printVersion := flag.Bool("version", false, "print connector protocol version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Println(connector.ProtocolVersion)
		os.Exit(0)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("grantor-connector: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gatewayAddr := os.Getenv("GRANTOR_CONNECTOR_GATEWAY_ADDR")
	if gatewayAddr == "" {
		return errors.New("GRANTOR_CONNECTOR_GATEWAY_ADDR is required")
	}
	serverName := os.Getenv("GRANTOR_CONNECTOR_GATEWAY_SERVER_NAME")
	if serverName == "" {
		host, _, err := net.SplitHostPort(gatewayAddr)
		if err != nil {
			return fmt.Errorf("parse gateway address %q: %w", gatewayAddr, err)
		}
		serverName = host
	}

	tlsCfg, err := clientTLSConfig(serverName)
	if err != nil {
		return err
	}
	verifier, err := loadVerifier()
	if err != nil {
		return err
	}

	// Регистрация adapters — явно в main (как в cmd/worker): состав engines,
	// которые этот connector умеет исполнять, виден в одном месте.
	adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	adapter.Register(mongodb.Engine, func() adapter.Adapter { return mongodb.New() })
	adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.New() })
	adapter.Register(rabbitmq.Engine, func() adapter.Adapter { return rabbitmq.New() })
	adapter.Register(clickhouse.Engine, func() adapter.Adapter { return clickhouse.New() })
	adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.New() })
	adapter.Register(redis.Engine, func() adapter.Adapter { return redis.New() })

	connectorID := serverutil.EnvOr("GRANTOR_CONNECTOR_ID", hostnameOr("connector"))
	ag, err := agent.New(agent.Config{
		ConnectorID:          connectorID,
		GatewayAddr:          gatewayAddr,
		TLS:                  tlsCfg,
		Verifier:             verifier,
		Capabilities:         registeredCapabilities(),
		NewAdapterWithDialer: guardedAdapter,
		Deployment:           detectDeployment(),
		Logger:               slog.Default(),
	})
	if err != nil {
		return err
	}

	slog.Info("grantor-connector: connecting to gateway",
		"gateway", gatewayAddr, "connector_id", connectorID,
		"protocol_version", connector.ProtocolVersion)
	return runWithReconnect(ctx, ag.Run)
}

// Пределы паузы между попытками подключения.
const (
	reconnectMinDelay = time.Second
	reconnectMaxDelay = 30 * time.Second
)

// runWithReconnect держит агента подключённым, пока жив контекст.
//
// Разрыв связи с gateway — штатное событие (перевыкат control plane,
// сетевой сбой), а не отказ конфигурации: выход из процесса перекладывал
// восстановление на рестарты пода, из-за чего недоступность gateway
// выглядела как CrashLoopBackOff и терялась в логах падений.
func runWithReconnect(ctx context.Context, run func(context.Context) error) error {
	delay := reconnectMinDelay
	for {
		err := run(ctx)
		if ctx.Err() != nil {
			// Остановка по сигналу — не ошибка соединения.
			return nil
		}
		slog.Warn("grantor-connector: gateway session ended; reconnecting",
			"error", err, "retry_in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(delay*2, reconnectMaxDelay)
	}
}

// clientTLSConfig собирает клиентский mTLS-конфиг connector из PEM клиентского
// сертификата/ключа и CA gateway.
func clientTLSConfig(serverName string) (*tls.Config, error) {
	certPEM, err := readRequiredFile("GRANTOR_CONNECTOR_TLS_CERT")
	if err != nil {
		return nil, err
	}
	keyPEM, err := readRequiredFile("GRANTOR_CONNECTOR_TLS_KEY")
	if err != nil {
		return nil, err
	}
	caPEM, err := readRequiredFile("GRANTOR_CONNECTOR_CA")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	roots, err := wire.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("load gateway CA: %w", err)
	}
	return wire.ClientTLSConfig(cert, roots, serverName)
}

// loadVerifier собирает верификатор подписей заданий из PEM Ed25519 публичного
// ключа gateway.
func loadVerifier() (connector.Verifier, error) {
	keyPEM, err := readRequiredFile("GRANTOR_CONNECTOR_VERIFY_KEY")
	if err != nil {
		return nil, err
	}
	pub, err := parseEd25519PublicKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load verify key: %w", err)
	}
	keyID := serverutil.EnvOr("GRANTOR_CONNECTOR_KEY_ID", "gateway")
	return connector.NewED25519Verifier(keyID, pub), nil
}

// parseEd25519PublicKey разбирает PEM-блок PKIX с Ed25519 публичным ключом.
func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519.PublicKey", key)
	}
	return pub, nil
}

// readRequiredFile читает файл, путь к которому задан переменной env; пустая
// переменная или ошибка чтения — ошибка старта.
func readRequiredFile(env string) ([]byte, error) {
	path := os.Getenv(env)
	if path == "" {
		return nil, fmt.Errorf("%s is required", env)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s (%s): %w", env, path, err)
	}
	return data, nil
}

// hostnameOr возвращает hostname или fallback, если его не удалось прочитать.
// registeredCapabilities собирает capabilities всех зарегистрированных
// adapters для Hello: gateway маршрутизирует задание connector'у только
// если тот объявил нужный engine, поэтому список обязан отражать реальный
// состав, а не один движок.
func registeredCapabilities() []adapter.Capability {
	seen := make(map[adapter.Capability]bool)
	caps := []adapter.Capability{connector.CapCredentialProofV1, connector.CapPrivateKubernetesDNSV1, connector.CapRedisNoAuthV1}
	for _, engine := range adapter.Engines() {
		a, err := adapter.New(engine)
		if err != nil {
			continue
		}
		for _, c := range a.Manifest().Capabilities {
			if seen[c] {
				continue
			}
			seen[c] = true
			caps = append(caps, c)
		}
	}
	return caps
}

func guardedAdapter(engine string, dial adapterutil.DialContextFunc) (adapter.Adapter, error) {
	switch engine {
	case postgres.Engine:
		return postgres.NewWithDialer(dial), nil
	case mongodb.Engine:
		return mongodb.NewWithDialer(dial), nil
	case mysql.Engine:
		return mysql.NewWithDialer(dial), nil
	case rabbitmq.Engine:
		return rabbitmq.NewWithDialer(dial), nil
	case clickhouse.Engine:
		return clickhouse.NewWithDialer(dial), nil
	case kafka.Engine:
		return kafka.NewWithDialer(dial), nil
	case redis.Engine:
		return redis.NewWithDialer(dial), nil
	default:
		return nil, errors.New("connector: engine does not support guarded target transport")
	}
}

func hostnameOr(fallback string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return fallback
}

// detectDeployment определяет среду агента для подсказки оператору:
// переменная GRANTOR_CONNECTOR_DEPLOYMENT сильнее автоопределения, иначе
// признак Kubernetes — служебные переменные, которые kubelet добавляет в
// каждый pod. Значение ни на что не влияет, кроме подписи в UI, поэтому
// неизвестное или неопределимое остаётся пустым.
func detectDeployment() string {
	if explicit := connector.NormalizeDeployment(os.Getenv("GRANTOR_CONNECTOR_DEPLOYMENT")); explicit != "" {
		return explicit
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return connector.DeploymentKubernetes
	}
	return connector.DeploymentVM
}
