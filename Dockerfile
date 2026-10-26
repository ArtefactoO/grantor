# Единый multi-call образ grantor (docs/architecture.md, раздел 27.2):
# все бинарники собираются в builder-стадии, runtime — distroless без
# shell и package manager, запуск не от root. Конкретный компонент
# выбирается через entrypoint (docker-compose переопределяет его).

ARG VERSION=dev

FROM golang:1.26 AS builder
WORKDIR /src

# Сначала только манифесты модуля: слой go mod download кэшируется и
# переживает правки исходников.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN set -eux; \
    mkdir -p /out; \
    for c in api worker connector connector-gateway migrate; do \
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
            -o "/out/grantor-${c}" "./cmd/${c}"; \
    done

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION
LABEL org.opencontainers.image.title="grantor" \
      org.opencontainers.image.source="https://github.com/ArtefactoO/grantor" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/ /usr/local/bin/

USER nonroot
ENTRYPOINT ["/usr/local/bin/grantor-api"]
