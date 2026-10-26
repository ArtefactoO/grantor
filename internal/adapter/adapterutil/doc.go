// Package adapterutil собирает плумбинг, общий для engine adapters
// (docs/architecture.md, раздел 10): построение TLS-конфигурации по режимам
// подключения, генерация паролей, разбор endpoint, сборка HTTP-транспорта и
// типовые шаги Plan/Apply/Verify. Логика извлечена из семи adapters
// (postgres, mysql, mongodb, rabbitmq, clickhouse, kafka, redis) без изменения
// поведения: каждый adapter вызывает эти функции вместо собственной копии.
//
// Идентификаторы и тексты ошибок — английские; секреты (пароли, приватные
// ключи) в тексты ошибок и результаты не попадают.
package adapterutil
