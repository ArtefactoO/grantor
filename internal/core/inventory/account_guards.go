package inventory

// Предикаты аккаунта, общие для API-слоя, worker и store. Вынесены в чистые
// функции без обращений к базе, чтобы правило проверялось юнит-тестом и было
// одним для всех вызывающих: расхождение guard'ов между ручками — то, как
// появились обе дыры, которые эти предикаты закрывают.

import (
	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// Значения accounts.kind (CHECK-ограничение схемы, миграция 00001).
const (
	// AccountKindLogin — учётная запись, которая может логиниться и потому
	// является носителем credential.
	AccountKindLogin = "login"
	// AccountKindGroup — роль/группа без логина: носитель прав, назначаемый
	// другим аккаунтам. Discovery заводит такую строку, чтобы показать её
	// членство, но credential у неё нет и быть не может.
	AccountKindGroup = "group"
)

// AccountHoldsCredential сообщает, что аккаунт вообще может быть носителем
// credential: только login. Список разрешающий, а не запрещающий — новый
// kind по умолчанию считается не-носителем, пока это не доказано явно.
//
// Операции credential lifecycle (create/adopt/rotate/share/restore) и
// lifecycle самого аккаунта (disable/enable/delete) применимы только к
// носителю credential. Для group/role они бессмысленны и опасны: у движков
// вроде PostgreSQL account.delete — это DROP ROLE, то есть уничтожение
// permission-роли и каскадный отзыв доступа у всех её членов.
func AccountHoldsCredential(a Account) bool {
	return a.Kind == AccountKindLogin
}

// CredentialPointerForeign сообщает, что vault_path ведёт в раздел
// принципала, которому аккаунт сейчас не принадлежит (в том числе когда
// принципала нет вовсе). Такой указатель — «висячий»: он выдал бы актуальный
// общий секрет ЧУЖОГО принципала, открывающий все его аккаунты в окружении.
//
// Собственный путь аккаунта (accounts/<id>/credential) и пустой путь
// foreign не бывают: они ни на какого принципала не ссылаются.
//
// ВАЖНО: то же правило продублировано SQL-выражением в
// Store.LinkAccountPrincipal (Go-функцию из UPDATE не вызвать). При
// изменении правила менять оба места вместе.
func CredentialPointerForeign(vaultPath string, principalID *uuid.UUID) bool {
	if !vault.IsPrincipalScopedPath(vaultPath) {
		return false
	}
	if principalID == nil {
		return true
	}
	return !vault.PathBelongsToPrincipal(vaultPath, principalID.String())
}

// AccountCredentialPointerForeign — CredentialPointerForeign для текущего
// состояния строки аккаунта.
func AccountCredentialPointerForeign(a Account) bool {
	return CredentialPointerForeign(a.VaultPath, a.PrincipalID)
}
