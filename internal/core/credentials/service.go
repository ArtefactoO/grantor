// Package credentials — lifecycle секретов учётных записей
// (docs/architecture.md, разделы 17 и 18). Vault — единственный источник
// истины: пароли живут в KV v2 по путям accounts/<id>/credential, в
// metadata database остаются только путь и несекретные метаданные.
// Yopass используется исключительно как канал одноразовой доставки
// секрета человеку.
//
// Инварианты безопасности (раздел 24): значения секретов не попадают в
// логи, ошибки, audit и ответы API (кроме одноразовой ссылки Yopass,
// которая возвращается вызывающему ровно один раз и нигде не
// сохраняется).
package credentials

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/yopass"
)

// DefaultShareTTL — TTL одноразовой ссылки по умолчанию (раздел 18).
const DefaultShareTTL = 24 * time.Hour

var (
	// ErrVaultNotConfigured возвращается, когда операция требует Vault,
	// а клиент Vault не сконфигурирован.
	ErrVaultNotConfigured = errors.New("credentials: vault is not configured")
	// ErrYopassNotConfigured возвращается, когда запрошена одноразовая
	// выдача, а клиент Yopass не сконфигурирован.
	ErrYopassNotConfigured = errors.New("credentials: yopass is not configured")
)

// Service — операции над credentials учётных записей. Оба клиента могут
// быть nil: тогда соответствующие операции возвращают понятную ошибку
// (ErrVaultNotConfigured/ErrYopassNotConfigured), а вызывающий переводит
// её в 503.
type Service struct {
	vault  *vault.Client
	yopass *yopass.Client
}

// NewService возвращает Service поверх переданных клиентов.
func NewService(vaultClient *vault.Client, yopassClient *yopass.Client) *Service {
	return &Service{vault: vaultClient, yopass: yopassClient}
}

// PutAccountCredential записывает credential учётной записи в Vault по
// пути accounts/<account-id>/credential и возвращает номер созданной
// версии и путь. Значения username/password в ошибки не попадают.
func (s *Service) PutAccountCredential(ctx context.Context, accountID uuid.UUID, username string, password []byte) (int, string, error) {
	if s.vault == nil {
		return 0, "", ErrVaultNotConfigured
	}
	if username == "" {
		return 0, "", errors.New("credentials: put account credential: username is empty")
	}
	if len(password) == 0 {
		return 0, "", errors.New("credentials: put account credential: password is empty")
	}
	path, err := vault.AccountCredentialPath(accountID.String())
	if err != nil {
		return 0, "", fmt.Errorf("credentials: put account credential: %w", err)
	}
	version, err := s.vault.Put(ctx, path, map[string]any{
		"username": username,
		"password": string(password),
	})
	if err != nil {
		return 0, "", fmt.Errorf("credentials: put account credential: %w", err)
	}
	return version, path, nil
}

// PutAccountAdoptProof записывает ПРОВЕРЯЕМЫЙ пароль adopt-режима
// verify_password во временный путь accounts/<account-id>/adopt-proof и
// возвращает номер созданной версии. Канонический accounts/<id>/credential при
// этом не трогается: пока target не подтвердил пароль, grantor не вправе
// объявлять его текущим паролем учётной записи (см.
// vault.AccountAdoptProofPath). Значения username/password в ошибки не
// попадают.
func (s *Service) PutAccountAdoptProof(ctx context.Context, accountID uuid.UUID, username string, password []byte) (int, error) {
	if s.vault == nil {
		return 0, ErrVaultNotConfigured
	}
	if username == "" {
		return 0, errors.New("credentials: put account adopt proof: username is empty")
	}
	if len(password) == 0 {
		return 0, errors.New("credentials: put account adopt proof: password is empty")
	}
	path, err := vault.AccountAdoptProofPath(accountID.String())
	if err != nil {
		return 0, fmt.Errorf("credentials: put account adopt proof: %w", err)
	}
	version, err := s.vault.Put(ctx, path, map[string]any{
		"username": username,
		"password": string(password),
	})
	if err != nil {
		return 0, fmt.Errorf("credentials: put account adopt proof: %w", err)
	}
	return version, nil
}

// GetAccountAdoptProofVersion читает ровно ту версию adopt-proof, которую
// закрепил API-слой. Версия пинится по той же причине, что и у
// account.restore: чтение latest позволило бы конкурентной записи подменить
// проверяемый пароль между enqueue и исполнением. Возвращённый password
// принадлежит вызывающему (после использования занулить clear).
func (s *Service) GetAccountAdoptProofVersion(ctx context.Context, accountID uuid.UUID, version int) (string, []byte, error) {
	if s.vault == nil {
		return "", nil, ErrVaultNotConfigured
	}
	if version <= 0 {
		return "", nil, errors.New("credentials: get account adopt proof: version must be positive")
	}
	path, err := vault.AccountAdoptProofPath(accountID.String())
	if err != nil {
		return "", nil, fmt.Errorf("credentials: get account adopt proof: %w", err)
	}
	data, err := s.vault.GetVersion(ctx, path, version)
	if err != nil {
		return "", nil, fmt.Errorf("credentials: get account adopt proof: %w", err)
	}
	username, _ := data["username"].(string)
	if username == "" {
		return "", nil, errors.New("credentials: get account adopt proof: username field is missing or empty")
	}
	passwordString, _ := data["password"].(string)
	if passwordString == "" {
		return "", nil, errors.New("credentials: get account adopt proof: password field is missing or empty")
	}
	password := make([]byte, len(passwordString))
	copy(password, passwordString)
	return username, password, nil
}

// DeleteAccountAdoptProof удаляет временный adopt-proof (все версии и
// метаданные). Вызывается и на успехе подтверждения (пароль уже переехал в
// accounts/<id>/credential), и на детерминированном отказе (неверный пароль):
// проверяемое значение не должно оставаться в Vault. Best-effort у
// вызывающего — отказ удаления не меняет исход операции.
func (s *Service) DeleteAccountAdoptProof(ctx context.Context, accountID uuid.UUID) error {
	if s.vault == nil {
		return ErrVaultNotConfigured
	}
	path, err := vault.AccountAdoptProofPath(accountID.String())
	if err != nil {
		return fmt.Errorf("credentials: delete account adopt proof: %w", err)
	}
	if err := s.vault.DeleteMetadata(ctx, path); err != nil {
		return fmt.Errorf("credentials: delete account adopt proof: %w", err)
	}
	return nil
}

// GetOwnAccountCredential читает ПОСЛЕДНЮЮ версию собственного credential
// учётной записи по каноническому пути accounts/<account-id>/credential и
// возвращает пароль, номер версии и сам путь. Используется adopt-flow:
// API-слой предварительно записывает заданный оператором пароль по этому
// пути, executor затем читает и применяет именно эту версию (pin по
// версии — см. credential.rotate), не полагаясь на account.vault_path,
// который у unmanaged-аккаунта ещё пуст. Возвращённый password — копия,
// принадлежащая вызывающему (после использования занулить clear).
func (s *Service) GetOwnAccountCredential(ctx context.Context, accountID uuid.UUID) ([]byte, int, string, error) {
	if s.vault == nil {
		return nil, 0, "", ErrVaultNotConfigured
	}
	path, err := vault.AccountCredentialPath(accountID.String())
	if err != nil {
		return nil, 0, "", fmt.Errorf("credentials: get own account credential: %w", err)
	}
	password, version, err := s.readVaultPassword(ctx, path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("credentials: get own account credential: %w", err)
	}
	return password, version, path, nil
}

// OwnAccountCredentialExists сообщает, владеет ли grantor собственным
// паролем учётной записи: проверяются несекретные metadata KV v2 по пути
// accounts/<id>/credential, значение пароля не читается. Зеркало
// PrincipalCredentialExists для второй топологии credential.
//
// Источник истины — именно Vault, а не account.vault_path: поле хранит
// намерение control plane и у аккаунта, принятого через adopt
// mode=metadata, пусто, тогда как секрет мог быть записан позднее (или
// наоборот — путь остался от удалённого секрета).
func (s *Service) OwnAccountCredentialExists(ctx context.Context, accountID uuid.UUID) (bool, error) {
	if s.vault == nil {
		return false, ErrVaultNotConfigured
	}
	path, err := vault.AccountCredentialPath(accountID.String())
	if err != nil {
		return false, fmt.Errorf("credentials: own account credential exists: %w", err)
	}
	if _, err := s.vault.Metadata(ctx, path); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("credentials: own account credential exists: %w", err)
	}
	return true, nil
}

// GetOwnAccountCredentialVersion читает ровно зарезервированную API версию
// собственного account credential. Restore обязан пинить версию: чтение
// latest позволило бы конкурентной записи Vault подменить credential между
// enqueue и execution. Возвращённый password принадлежит вызывающему.
func (s *Service) GetOwnAccountCredentialVersion(ctx context.Context, accountID uuid.UUID, version int) (string, []byte, string, error) {
	if s.vault == nil {
		return "", nil, "", ErrVaultNotConfigured
	}
	if version <= 0 {
		return "", nil, "", errors.New("credentials: get own account credential version: version must be positive")
	}
	path, err := vault.AccountCredentialPath(accountID.String())
	if err != nil {
		return "", nil, "", fmt.Errorf("credentials: get own account credential version: %w", err)
	}
	data, err := s.vault.GetVersion(ctx, path, version)
	if err != nil {
		return "", nil, "", fmt.Errorf("credentials: get own account credential version: %w", err)
	}
	username, _ := data["username"].(string)
	if username == "" {
		return "", nil, "", errors.New("credentials: get own account credential version: username field is missing or empty")
	}
	passwordString, _ := data["password"].(string)
	if passwordString == "" {
		return "", nil, "", errors.New("credentials: get own account credential version: password field is missing or empty")
	}
	password := make([]byte, len(passwordString))
	copy(password, passwordString)
	return username, password, path, nil
}

// GetAccountCredential читает актуальную версию credential учётной записи
// из Vault по её фактическому пути (account.vault_path: для собственного
// креда это accounts/<id>/credential, для credential_mode=existing_vault_ref
// — общий путь принципала principals/<id>/environments/<env>/credential).
// Общий секрет принципала хранит только password, поэтому при отсутствии
// поля username используется fallbackUsername (engine identity аккаунта).
// Возвращённый password — копия, которой владеет вызывающий: после
// использования байты стоит занулить (clear).
func (s *Service) GetAccountCredential(ctx context.Context, path, fallbackUsername string) (string, []byte, error) {
	username, password, _, err := s.GetAccountCredentialSnapshot(ctx, path, fallbackUsername)
	return username, password, err
}

// GetAccountCredentialSnapshot returns the exact version read along with its
// owned password bytes. Callers may pin it before any target mutation.
func (s *Service) GetAccountCredentialSnapshot(ctx context.Context, path, fallbackUsername string) (string, []byte, int, error) {
	if s.vault == nil {
		return "", nil, 0, ErrVaultNotConfigured
	}
	if path == "" {
		return "", nil, 0, errors.New("credentials: get account credential: vault path is empty")
	}
	data, version, err := s.vault.Get(ctx, path)
	if err != nil {
		return "", nil, 0, fmt.Errorf("credentials: get account credential: %w", err)
	}
	username, _ := data["username"].(string)
	if username == "" {
		username = fallbackUsername
	}
	if username == "" {
		return "", nil, 0, errors.New("credentials: get account credential: username field is missing or empty")
	}
	passwordStr, _ := data["password"].(string)
	if passwordStr == "" {
		return "", nil, 0, errors.New("credentials: get account credential: password field is missing or empty")
	}
	password := make([]byte, len(passwordStr))
	copy(password, passwordStr)
	return username, password, version, nil
}

// GetAccountCredentialVersion читает конкретную версию credential по уже
// проверенному вызывающим Vault path. Нужен restore linked principal-account:
// операция пинит ту версию общего секрета, которая была актуальна при enqueue,
// и retry не может незаметно применить другую ротацию.
func (s *Service) GetAccountCredentialVersion(ctx context.Context, path, fallbackUsername string, version int) (string, []byte, error) {
	if s.vault == nil {
		return "", nil, ErrVaultNotConfigured
	}
	if path == "" || version <= 0 {
		return "", nil, errors.New("credentials: get account credential version: path and positive version are required")
	}
	data, err := s.vault.GetVersion(ctx, path, version)
	if err != nil {
		return "", nil, fmt.Errorf("credentials: get account credential version: %w", err)
	}
	username, _ := data["username"].(string)
	if username == "" {
		username = fallbackUsername
	}
	if username == "" {
		return "", nil, errors.New("credentials: get account credential version: username is missing")
	}
	passwordString, _ := data["password"].(string)
	if passwordString == "" {
		return "", nil, errors.New("credentials: get account credential version: password is missing")
	}
	password := make([]byte, len(passwordString))
	copy(password, passwordString)
	return username, password, nil
}

// ownAccountCredentialPath сообщает, что путь — собственный кред аккаунта
// (accounts/<id>/credential), а не общий секрет принципала
// (principals/...): только собственный кред можно удалять вместе с
// аккаунтом — общим пользуются другие аккаунты того же принципала.
func ownAccountCredentialPath(path string) bool {
	return strings.HasPrefix(path, "accounts/")
}

// DeleteAccountCredential удаляет собственный кред аккаунта из Vault (все
// версии и метаданные). Путь общего секрета принципала — no-op без ошибки:
// вызывающему не нужно различать режимы credential. Используется зачисткой
// после успешного account.delete; сам вызов best-effort у вызывающего.
func (s *Service) DeleteAccountCredential(ctx context.Context, path string) error {
	if path == "" || !ownAccountCredentialPath(path) {
		return nil
	}
	if s.vault == nil {
		return ErrVaultNotConfigured
	}
	if err := s.vault.DeleteMetadata(ctx, path); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("credentials: delete account credential: %w", err)
	}
	return nil
}

// ShareAccountCredential читает credential учётной записи из Vault по её
// фактическому пути (см. GetAccountCredential) и выдаёт одноразовую
// ссылку Yopass с текстом "username: X\npassword: Y". ttl <= 0 заменяется
// DefaultShareTTL (24h); значение обязано совпадать с одним из TTL,
// поддерживаемых Yopass (1h/1d/1w).
//
// Ссылка возвращается ровно один раз и нигде не сохраняется; секретные
// байты зануляются перед возвратом.
func (s *Service) ShareAccountCredential(ctx context.Context, path, fallbackUsername string, ttl time.Duration) (string, error) {
	if s.yopass == nil {
		return "", ErrYopassNotConfigured
	}
	username, password, err := s.GetAccountCredential(ctx, path, fallbackUsername)
	if err != nil {
		return "", fmt.Errorf("credentials: share account credential: %w", err)
	}
	message := shareMessage(username, password)
	defer func() {
		clear(message)
		clear(password)
	}()

	if ttl <= 0 {
		ttl = DefaultShareTTL
	}
	link, err := s.yopass.Share(ctx, message, int(ttl/time.Second), true)
	if err != nil {
		return "", fmt.Errorf("credentials: share account credential: %w", err)
	}
	return link, nil
}

// shareMessage собирает текст одноразового сообщения. Отдельная функция
// без обращений к Vault/Yopass, чтобы формат проверялся юнит-тестом.
func shareMessage(username string, password []byte) []byte {
	message := make([]byte, 0, len("username: \npassword: ")+len(username)+len(password))
	message = append(message, "username: "...)
	message = append(message, username...)
	message = append(message, "\npassword: "...)
	message = append(message, password...)
	return message
}
