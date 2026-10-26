package vault

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultMount — KV v2 mount grantor по умолчанию (docs/architecture.md,
// раздел 17.2). Функции путей возвращают относительные пути без mount:
// mount задаётся один раз в Config и подставляется клиентом.
const DefaultMount = "grantor"

// ValidateID проверяет идентификатор для использования как сегмент Vault
// path: он должен быть непустым и не содержать '/'. Идентификаторы grantor
// не секретны, поэтому попадание id в текст ошибки допустимо.
func ValidateID(id string) error {
	if id == "" {
		return errors.New("vault: empty id")
	}
	if strings.Contains(id, "/") {
		return fmt.Errorf("vault: id %q must not contain '/'", id)
	}
	return nil
}

// ConnectionAdminPath возвращает путь admin credential подключения:
// "connections/<connection-id>/admin". Функции путей валидируют id сами и
// возвращают ошибку вместо panic, чтобы некорректный id из внешнего ввода
// не ронял процесс и не превращался в чужой Vault path.
func ConnectionAdminPath(connectionID string) (string, error) {
	if err := ValidateID(connectionID); err != nil {
		return "", fmt.Errorf("connection admin path: %w", err)
	}
	return fmt.Sprintf("connections/%s/admin", connectionID), nil
}

// ConnectionAdminChangeStagePath returns the operation-scoped candidate path
// used by admin credential switch/rotation. The operation id is also the
// public request_id, so a lost API response resolves to the same Vault object
// without storing secret material in PostgreSQL.
func ConnectionAdminChangeStagePath(connectionID, operationID string) (string, error) {
	if err := ValidateID(connectionID); err != nil {
		return "", fmt.Errorf("connection admin change stage path: %w", err)
	}
	if err := ValidateID(operationID); err != nil {
		return "", fmt.Errorf("connection admin change stage path: %w", err)
	}
	return fmt.Sprintf("connections/%s/admin-changes/%s", connectionID, operationID), nil
}

// AccountCredentialPath возвращает путь credential учётной записи:
// "accounts/<account-id>/credential".
func AccountCredentialPath(accountID string) (string, error) {
	if err := ValidateID(accountID); err != nil {
		return "", fmt.Errorf("account credential path: %w", err)
	}
	return fmt.Sprintf("accounts/%s/credential", accountID), nil
}

// AccountAdoptProofPath возвращает путь ВРЕМЕННОГО секрета, который проверяет
// adopt в режиме verify_password: "accounts/<account-id>/adopt-proof".
//
// Отдельный путь принципиален: пароль, который оператор просит подтвердить,
// ещё ничем не доказан, и до успеха подтверждения ему нельзя лежать по
// каноническому accounts/<id>/credential — иначе опечатка оставила бы там
// «неактивированную» версию, которую следующая ротация или share выдали бы за
// текущий пароль учётной записи. Vault здесь — единственный доступный канал
// «API -> worker» для секрета (в payload операции секретов нет по инварианту),
// поэтому значение кладётся сюда, читается ровно один раз по закреплённой
// версии и удаляется и на успехе, и на детерминированном отказе.
func AccountAdoptProofPath(accountID string) (string, error) {
	if err := ValidateID(accountID); err != nil {
		return "", fmt.Errorf("account adopt proof path: %w", err)
	}
	return fmt.Sprintf("accounts/%s/adopt-proof", accountID), nil
}

// ConnectorIdentityPath возвращает путь identity коннектора:
// "connectors/<connector-id>/identity".
func ConnectorIdentityPath(connectorID string) (string, error) {
	if err := ValidateID(connectorID); err != nil {
		return "", fmt.Errorf("connector identity path: %w", err)
	}
	return fmt.Sprintf("connectors/%s/identity", connectorID), nil
}

// PrincipalEnvironmentCredentialPath возвращает путь общего секрета
// принципала в конкретном окружении:
// "principals/<principal-id>/environments/<environment>/credential".
//
// Модель shared-per-principal-per-environment: один пароль принципала
// переиспользуется всеми его managed-аккаунтами в подключениях одного
// окружения (у каждого account свой username = engine_identity, но пароль
// общий), при этом в разных окружениях пароли независимы. Оба сегмента
// пути валидируются как id (непустые, без '/').
func PrincipalEnvironmentCredentialPath(principalID, environment string) (string, error) {
	if err := ValidateID(principalID); err != nil {
		return "", fmt.Errorf("principal environment credential path: %w", err)
	}
	if err := ValidateID(environment); err != nil {
		return "", fmt.Errorf("principal environment credential path: %w", err)
	}
	return fmt.Sprintf("%s%s/environments/%s/credential", PrincipalPathPrefix, principalID, environment), nil
}

// PrincipalPathPrefix — общий префикс всех путей, скоупленных принципалом.
// Экспортируется, чтобы SQL-выражения metadata database (которые не могут
// вызвать Go-функции ниже) сравнивались с тем же литералом, а не с копией.
const PrincipalPathPrefix = "principals/"

// IsPrincipalScopedPath сообщает, что путь ведёт в раздел принципала
// (общий секрет пары principal+environment), а не в собственный раздел
// аккаунта accounts/<id>/credential.
func IsPrincipalScopedPath(path string) bool {
	return strings.HasPrefix(path, PrincipalPathPrefix)
}

// PathBelongsToPrincipal сообщает, что principal-scoped путь принадлежит
// именно principalID. Для непринципальных путей возвращает false: вопрос
// принадлежности к принципалу для них не определён, и вызывающий обязан
// сначала спросить IsPrincipalScopedPath.
//
// Сравнение префиксное и включает завершающий '/': иначе принципал с id
// "a" совпал бы с путём принципала "ab". Пустой principalID не принадлежит
// ничему.
func PathBelongsToPrincipal(path, principalID string) bool {
	if principalID == "" || !IsPrincipalScopedPath(path) {
		return false
	}
	return strings.HasPrefix(path, PrincipalPathPrefix+principalID+"/")
}
