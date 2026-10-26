package migrations

// LockKey — ключ session advisory lock, сериализующего применение
// миграций над одной базой между параллельными процессами: тестовыми
// пакетами (internal/testutil/pgtest) и запусками db-migrate Job
// (cmd/migrate). Единая точка истины: ключ обязан совпадать у всех, кто
// применяет миграции.
const LockKey = int64(0x6772616e746f72) // "grantor"
