# Все проверки, сборки и миграции выполняются в Docker-контейнерах — локальный
# Go toolchain не используется и не требуется. Образы совпадают с CI.

GO_IMAGE    ?= golang:1.26
LINT_IMAGE  ?= golangci/golangci-lint:v2.12
GOOSE_IMAGE ?= ghcr.io/pressly/goose:latest

# Кеши модулей, сборки и линтера живут в named volume между запусками.
CACHE_VOLUME ?= grantor-build-cache

DOCKER_RUN = docker run --rm \
	-v $(CURDIR):/src -w /src \
	-v $(CACHE_VOLUME):/cache \
	-e GOMODCACHE=/cache/gomod \
	-e GOCACHE=/cache/gobuild \
	-e GOLANGCI_LINT_CACHE=/cache/golangci-lint

.PHONY: lint test test-integration build bins tidy web-test web-build up down logs migrate-up migrate-status clean-cache

lint:
	$(DOCKER_RUN) $(LINT_IMAGE) golangci-lint run ./...

test:
	$(DOCKER_RUN) $(GO_IMAGE) go test -race -count=1 ./...

# Ephemeral PostgreSQL + Vault в Docker, тесты с тегом integration.
test-integration:
	./scripts/test-integration.sh

build:
	$(DOCKER_RUN) $(GO_IMAGE) go build ./...

bins:
	$(DOCKER_RUN) -e CGO_ENABLED=0 $(GO_IMAGE) sh -c '\
		mkdir -p bin && \
		for c in api worker connector connector-gateway; do \
			go build -o bin/grantor-$$c ./cmd/$$c; \
		done'

tidy:
	$(DOCKER_RUN) $(GO_IMAGE) go mod tidy

NODE_IMAGE ?= node:22-alpine
WEB_CACHE_VOLUME ?= grantor-web-npm-cache

WEB_DOCKER_RUN = docker run --rm \
	-v $(CURDIR)/web:/app -w /app \
	-v /app/node_modules \
	-v $(WEB_CACHE_VOLUME):/npm-cache \
	$(NODE_IMAGE)

web-test:
	$(WEB_DOCKER_RUN) \
		sh -c 'npm ci --no-audit --no-fund --cache /npm-cache && npm run test'

web-build:
	$(WEB_DOCKER_RUN) \
		sh -c 'npm ci --no-audit --no-fund --cache /npm-cache && npm run build'

# Dev-контур: PostgreSQL + Vault (dev) + migrate + api + worker.
# Host-порты: postgres 55432, vault 58200, api 58080, worker 58081.
up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

# GRANTOR_DB_DSN, например:
#   postgres://user:pass@host.docker.internal:5432/grantor?sslmode=disable
# (goose выполняется в контейнере, поэтому localhost — это host.docker.internal)
migrate-up:
	docker run --rm -v $(CURDIR)/db/migrations:/migrations \
		$(GOOSE_IMAGE) -dir /migrations postgres "$(GRANTOR_DB_DSN)" up

migrate-status:
	docker run --rm -v $(CURDIR)/db/migrations:/migrations \
		$(GOOSE_IMAGE) -dir /migrations postgres "$(GRANTOR_DB_DSN)" status

clean-cache:
	docker volume rm $(CACHE_VOLUME)
