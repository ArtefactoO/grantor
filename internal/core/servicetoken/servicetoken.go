// Package servicetoken — выпуск, хранение и проверка service tokens для
// машинного доступа к API (ADR-0007; docs/threat-model.md, P1 machine access,
// R10). Токен формата grt_<base64url> предъявляется в заголовке
// Authorization: Bearer. В базе хранится только sha256-хекс токена
// (token_hash) — сам токен возвращается вызывающему ровно один раз при
// выпуске и больше нигде не сохраняется и не логируется.
//
// Выпуск/отзыв — операция admin; выпуск возможен только для принципала
// type=service. Аутентификация по токену собирает сессию с ролью operator
// (см. internal/api): машине нужны мутации в пределах её scope policies.
package servicetoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// TokenPrefix — префикс plaintext-токена. Помогает распознать service token в
// заголовке Authorization и грепать возможные утечки.
const TokenPrefix = "grt_"

// tokenRandomBytes — длина случайной части токена в байтах до
// base64url-кодирования. 30 байт = 240 бит энтропии; base64url без паддинга
// даёт 40 символов, плюс префикс — итоговая длина 44.
const tokenRandomBytes = 30

// GenerateToken возвращает новый plaintext-токен формата grt_<base64url>.
// Значение отдаётся вызывающему один раз: в базу кладётся только HashToken.
func GenerateToken() (string, error) {
	b := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("servicetoken: generate: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken возвращает sha256-хекс токена — значение, которое хранится в
// колонке token_hash. От самого токена в базу не попадает ничего.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HasTokenPrefix сообщает, похоже ли значение на service token. Используется
// для быстрого отсева не-service Authorization-заголовков до обращения к базе.
func HasTokenPrefix(token string) bool {
	return strings.HasPrefix(token, TokenPrefix)
}
