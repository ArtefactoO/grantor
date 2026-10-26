package credentials

// Общий секрет принципала (модель shared-per-principal-per-environment,
// решение пользователя): ОДИН пароль на пару (principal, environment),
// переиспользуемый всеми managed-аккаунтами принципала в подключениях
// этого окружения. Секрет живёт в Vault по пути
// principals/<id>/environments/<env>/credential и содержит одно поле
// password: username у каждого account свой (engine_identity), общий
// только пароль.
//
// Инварианты безопасности прежние (раздел 24): значения паролей не
// попадают в логи, ошибки, audit и ответы API; байты зануляются после
// использования.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// DefaultPasswordLength — длина генерируемого движко-независимого пароля.
const DefaultPasswordLength = 32

// passwordAlphabet — алфавит генерируемых паролей: [A-Za-z0-9]. Без
// спецсимволов, чтобы пароль был безопасен для строк подключения любого
// движка (PostgreSQL/MySQL/Mongo/RabbitMQ).
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GeneratePassword возвращает криптослучайный пароль из алфавита
// [A-Za-z0-9] длиной length (length <= 0 заменяется DefaultPasswordLength).
// Движко-независимый генератор нужен общему секрету принципала: один
// пароль применяется в кластерах разных движков, поэтому нельзя опираться
// на генератор конкретного adapter.
//
// Распределение равномерно: байты вне наибольшего кратного длине алфавита
// диапазона отбрасываются (rejection sampling), чтобы modulo не вносил
// смещения.
func GeneratePassword(length int) ([]byte, error) {
	if length <= 0 {
		length = DefaultPasswordLength
	}
	n := len(passwordAlphabet)
	limit := 256 - (256 % n)
	out := make([]byte, length)
	buf := make([]byte, 1)
	for i := 0; i < length; {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("credentials: generate password: %w", err)
		}
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = passwordAlphabet[int(buf[0])%n]
		i++
	}
	return out, nil
}

// GetPasswordByPath читает поле password секрета по произвольному
// относительному пути Vault и возвращает его копию вместе с версией.
// Используется executor для чтения общего секрета принципала по пути из
// payload операции. Возвращённый password принадлежит вызывающему: после
// использования байты стоит занулить (clear).
func (s *Service) GetPasswordByPath(ctx context.Context, path string) ([]byte, int, error) {
	if s.vault == nil {
		return nil, 0, ErrVaultNotConfigured
	}
	password, version, err := s.readVaultPassword(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("credentials: get password by path: %w", err)
	}
	return password, version, nil
}

// readVaultPassword читает поле password секрета Vault по пути и возвращает
// его копию и версию. Значение password в ошибки не попадает.
func (s *Service) readVaultPassword(ctx context.Context, path string) ([]byte, int, error) {
	data, version, err := s.vault.Get(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	passwordStr, _ := data["password"].(string)
	if passwordStr == "" {
		return nil, 0, errors.New("password field is missing or empty")
	}
	password := make([]byte, len(passwordStr))
	copy(password, passwordStr)
	return password, version, nil
}

// EnsurePrincipalCredential гарантирует наличие общего секрета принципала
// для окружения. Если секрет уже есть — возвращает путь и created=false,
// не трогая существующий пароль (несколько аккаунтов principal ССЫЛАЮТСЯ
// на один секрет). Иначе генерирует пароль через переданный generate,
// записывает его в Vault и возвращает created=true. generate обязан
// вернуть движко-независимый пароль (см. GeneratePassword).
//
// Идемпотентность относительно гонок best-effort: если Put не удался, но
// секрет уже читается (его создал конкурентный вызов), возвращается
// существующий путь с created=false. Полная защита от гонки «оба видят
// отсутствие секрета» потребовала бы Vault CAS; TODO(этап 1): создавать
// секрет с cas=0.
func (s *Service) EnsurePrincipalCredential(ctx context.Context, principalID uuid.UUID, environment string, generate func() ([]byte, error)) (string, bool, error) {
	if s.vault == nil {
		return "", false, ErrVaultNotConfigured
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	if err != nil {
		return "", false, fmt.Errorf("credentials: ensure principal credential: %w", err)
	}

	_, _, getErr := s.vault.Get(ctx, path)
	switch {
	case getErr == nil:
		return path, false, nil
	case !errors.Is(getErr, vault.ErrNotFound):
		return "", false, fmt.Errorf("credentials: ensure principal credential: %w", getErr)
	}

	password, err := generate()
	if err != nil {
		return "", false, fmt.Errorf("credentials: ensure principal credential: generate: %w", err)
	}
	defer clear(password)
	if len(password) == 0 {
		return "", false, errors.New("credentials: ensure principal credential: generated password is empty")
	}
	if _, err := s.vault.Put(ctx, path, map[string]any{"password": string(password)}); err != nil {
		// Возможная гонка: секрет мог появиться между Get и Put. Перечитываем.
		if _, _, getErr := s.vault.Get(ctx, path); getErr == nil {
			return path, false, nil
		}
		return "", false, fmt.Errorf("credentials: ensure principal credential: %w", err)
	}
	return path, true, nil
}

// GetPrincipalCredential читает актуальный общий пароль принципала для
// окружения и возвращает его копию с версией. Байты стоит занулить после
// использования.
func (s *Service) GetPrincipalCredential(ctx context.Context, principalID uuid.UUID, environment string) ([]byte, int, error) {
	if s.vault == nil {
		return nil, 0, ErrVaultNotConfigured
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	if err != nil {
		return nil, 0, fmt.Errorf("credentials: get principal credential: %w", err)
	}
	password, version, err := s.readVaultPassword(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("credentials: get principal credential: %w", err)
	}
	return password, version, nil
}

// PrincipalCredentialExists проверяет наличие общего credential по
// несекретным metadata KV v2. Значение password при этом не читается и не
// попадает в память API-процесса.
func (s *Service) PrincipalCredentialExists(ctx context.Context, principalID uuid.UUID, environment string) (bool, error) {
	if s.vault == nil {
		return false, ErrVaultNotConfigured
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	if err != nil {
		return false, fmt.Errorf("credentials: principal credential exists: %w", err)
	}
	if _, err := s.vault.Metadata(ctx, path); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("credentials: principal credential exists: %w", err)
	}
	return true, nil
}

// RotatePrincipalCredential записывает новую версию общего секрета
// принципала для окружения и возвращает её номер. Применение нового пароля
// к аккаунтам principal выполняется отдельными credential.rotate
// операциями (по одной на кластер, best-effort).
func (s *Service) RotatePrincipalCredential(ctx context.Context, principalID uuid.UUID, environment string, newPassword []byte) (int, error) {
	if s.vault == nil {
		return 0, ErrVaultNotConfigured
	}
	if len(newPassword) == 0 {
		return 0, errors.New("credentials: rotate principal credential: password is empty")
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	if err != nil {
		return 0, fmt.Errorf("credentials: rotate principal credential: %w", err)
	}
	version, err := s.vault.Put(ctx, path, map[string]any{"password": string(newPassword)})
	if err != nil {
		return 0, fmt.Errorf("credentials: rotate principal credential: %w", err)
	}
	return version, nil
}

// principalCredentialPath сообщает, что путь — общий секрет принципала
// (префикс principals/). Guard удаления: DeletePrincipalCredential не
// должен уметь удалять чужие секреты (connections/, accounts/,
// connectors/) даже при ошибке в построении пути — зеркало
// ownAccountCredentialPath для противоположного направления.
func principalCredentialPath(path string) bool {
	return strings.HasPrefix(path, "principals/")
}

// DeletePrincipalCredential удаляет общий секрет принципала для окружения
// из Vault (все версии и метаданные). Используется offboarding
// принципала: после постановки детей (revoke + delete его аккаунтов)
// общий секрет вычищается сразу на API-этапе — удаляемые аккаунты им
// больше не пользуются, а retry упавшего ребёнка идёт под admin
// credential подключения и общий секрет не читает. Удаляются только пути
// с префиксом principals/ (см. principalCredentialPath); чужой префикс —
// ошибка, а не тихий проход.
func (s *Service) DeletePrincipalCredential(ctx context.Context, principalID uuid.UUID, environment string) error {
	if s.vault == nil {
		return ErrVaultNotConfigured
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	if err != nil {
		return fmt.Errorf("credentials: delete principal credential: %w", err)
	}
	if !principalCredentialPath(path) {
		return fmt.Errorf("credentials: delete principal credential: path %q is outside principals/", path)
	}
	if err := s.vault.DeleteMetadata(ctx, path); err != nil {
		return fmt.Errorf("credentials: delete principal credential: %w", err)
	}
	return nil
}

// SharePrincipalCredential читает общий пароль принципала для окружения и
// выдаёт одноразовую ссылку Yopass. ttl <= 0 заменяется DefaultShareTTL
// (24h). Ссылка возвращается ровно один раз и нигде не сохраняется;
// секретные байты зануляются перед возвратом.
func (s *Service) SharePrincipalCredential(ctx context.Context, principalID uuid.UUID, userLabel string, logins []string, environment string, ttl time.Duration) (string, error) {
	if s.yopass == nil {
		return "", ErrYopassNotConfigured
	}
	userLabel = strings.Join(strings.Fields(userLabel), " ")
	if userLabel == "" {
		return "", errors.New("credentials: share principal credential: user label is empty")
	}
	password, _, err := s.GetPrincipalCredential(ctx, principalID, environment)
	if err != nil {
		return "", fmt.Errorf("credentials: share principal credential: %w", err)
	}
	message := principalShareMessage(userLabel, logins, environment, password)
	defer func() {
		clear(message)
		clear(password)
	}()

	if ttl <= 0 {
		ttl = DefaultShareTTL
	}
	link, err := s.yopass.Share(ctx, message, int(ttl/time.Second), true)
	if err != nil {
		return "", fmt.Errorf("credentials: share principal credential: %w", err)
	}
	return link, nil
}

// principalShareMessage собирает текст одноразового сообщения для общего
// секрета принципала. Кроме видимого имени пользователя выводится login —
// без него получатель знал только пароль и не знал, кем подключаться. Один
// пароль окружения могут использовать несколько аккаунтов с разными
// логинами, поэтому login принимает список. Отдельная функция без обращений
// к Vault/Yopass, чтобы формат проверялся юнит-тестом.
func principalShareMessage(userLabel string, logins []string, environment string, password []byte) []byte {
	prefix := "user: " + userLabel + "\n"
	if len(logins) > 0 {
		prefix += "login: " + strings.Join(logins, ", ") + "\n"
	}
	prefix += "environment: " + environment + "\npassword: "
	message := make([]byte, 0, len(prefix)+len(password))
	message = append(message, prefix...)
	message = append(message, password...)
	return message
}
