package api

import (
	"context"
	"time"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
)

// serviceTokenTTL — номинальный срок жизни сессии, собранной по service-токену.
// Token-сессия живёт один запрос и не сериализуется в cookie; ExpiresAt задаётся
// ради единообразия формата и в проверках не участвует (Decode её не читает).
const serviceTokenTTL = time.Hour

// serviceTokenAuthenticator реализует auth.TokenAuthenticator: аутентифицирует
// запрос по service-токену (Authorization: Bearer grt_...) и собирает сессию
// service-принципала с ролью operator. Живёт в api-слое: выбор роли и actor
// identity — авторизационная политика, а не свойство самого токена.
type serviceTokenAuthenticator struct {
	q     servicetoken.Querier
	store *servicetoken.Store
}

// NewServiceTokenAuth возвращает auth.TokenAuthenticator, аутентифицирующий
// service-токены через store поверх q (пул metadata database). Передаётся в
// auth.Config.TokenAuth (wiring cmd/api и тесты).
func NewServiceTokenAuth(q servicetoken.Querier, store *servicetoken.Store) auth.TokenAuthenticator {
	return serviceTokenAuthenticator{q: q, store: store}
}

// AuthenticateToken проверяет токен и возвращает сессию service-принципала с
// ролью operator. Роль operator, а не admin: машине обычно нужны мутации в
// пределах своих scope policies, и service-принципал ограничивается ими так же,
// как человек-operator. Service=true снимает требование CSRF (нет cookie) и
// даёт actor_type=service в audit/operations. ok=false при любой ошибке — без
// различения причины, чтобы не давать оракул.
func (a serviceTokenAuthenticator) AuthenticateToken(ctx context.Context, token string) (auth.Session, bool) {
	principal, permissions, err := a.store.AuthenticateWithPermissions(ctx, a.q, token)
	if err != nil {
		return auth.Session{}, false
	}
	return auth.Session{
		Subject:     principal.ID.String(),
		Email:       principal.DisplayName,
		Role:        auth.RoleOperator,
		Service:     true,
		Permissions: permissions,
		ExpiresAt:   time.Now().Add(serviceTokenTTL),
	}, true
}
