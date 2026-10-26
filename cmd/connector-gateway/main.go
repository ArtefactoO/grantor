// Command grantor-connector-gateway терминирует mTLS-соединения execution
// connectors и диспетчеризует им подписанные задания (docs/architecture.md,
// разделы 4.3, 24 и 27.1; ADR-0002, ADR-0006).
//
// Standalone-бинарь поднимает mTLS-сервер (обязательная верификация
// клиентского сертификата connector), выполняет version-negotiation handshake
// и держит сессию подключённого connector; выдача заданий доступна через
// Go-API gateway.Dispatch. С этапа 2 основной хост gateway — worker-процесс
// (cmd/worker, GRANTOR_CONNECTOR_LISTEN): он же источник заданий через
// operation engine и durable-дедупликация в metadata DB. Standalone-бинарь
// сохранён для запуска без metadata DB (дедупликация — in-memory) и отладки;
// оба хоста используют один пакет internal/connector/gateway и одни
// переменные окружения.
//
// # Транспорт
//
// stdlib crypto/tls + length-prefixed фрейминг Envelope (пакет
// internal/connector/wire). ConnectRPC — целевой транспорт (ADR-0002); контракт
// задания/подписи транспортонезависим, поэтому замена не затронет operation
// engine.
//
// # Окружение
//
//   - GRANTOR_CONNECTOR_GATEWAY_LISTEN — адрес прослушивания, по умолчанию
//     ":8443".
//   - GRANTOR_CONNECTOR_GATEWAY_TLS_CERT / _TLS_KEY — PEM серверного
//     сертификата и приватного ключа gateway. Обязательны.
//   - GRANTOR_CONNECTOR_GATEWAY_CLIENT_CA — PEM CA, которым подписаны
//     клиентские сертификаты connector (mTLS identity). Обязателен.
//   - GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY — PEM Ed25519 приватного ключа
//     (PKCS#8), которым gateway подписывает задания. Обязателен.
//   - GRANTOR_CONNECTOR_GATEWAY_KEY_ID — идентификатор ключа подписи (KeyID в
//     Envelope), по умолчанию "gateway".
//
// Флаг -version печатает версию протокола и завершается кодом 0.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
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
		slog.Error("grantor-connector-gateway: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listen := serverutil.EnvOr("GRANTOR_CONNECTOR_GATEWAY_LISTEN", ":8443")

	// Dedup и наблюдатель сессий nil: standalone-бинарь работает без
	// metadata DB — durable-дедупликацию и наблюдения подключает
	// worker-хост (cmd/worker).
	srv, err := gateway.NewServerFromEnv(slog.Default(), nil, nil)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	slog.Info("grantor-connector-gateway: listening",
		"listen", listen, "protocol_version", connector.ProtocolVersion,
		"note", "standalone host: in-memory dedup; operation engine routing lives in grantor-worker")

	select {
	case <-ctx.Done():
		slog.Info("grantor-connector-gateway: shutting down")
	case err := <-serveErr:
		if err != nil {
			_ = ln.Close()
			_ = srv.Close()
			return err
		}
	}
	_ = ln.Close()
	return srv.Close()
}
