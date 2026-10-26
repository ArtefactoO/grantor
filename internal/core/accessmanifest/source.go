package accessmanifest

// storeSource — реализация Source поверх сторов ядра и одного Querier.
// Резолв имён (principal/connection/permission) читает списки лениво и
// кэширует их на время одного вызова Plan/Export: манифест обычно ссылается
// на одни и те же подключения многократно, а снапшот в пределах запроса
// делает резолв согласованным.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// principalPageSize — размер страницы при вычитывании всех принципалов для
// резолва по имени.
const principalPageSize = 500

type storeSource struct {
	connections *connections.Store
	principals  *principals.Store
	inventory   *inventory.Store
	q           Querier

	connList    []connections.Connection
	connLoaded  bool
	princList   []principals.Principal
	princLoaded bool
	permCache   map[uuid.UUID][]inventory.Permission
}

var _ Source = (*storeSource)(nil)

// loadConnections лениво вычитывает и кэширует все подключения.
func (s *storeSource) loadConnections(ctx context.Context) error {
	if s.connLoaded {
		return nil
	}
	list, err := s.connections.List(ctx, s.q)
	if err != nil {
		return fmt.Errorf("accessmanifest: load connections: %w", err)
	}
	s.connList = list
	s.connLoaded = true
	return nil
}

// loadPrincipals лениво вычитывает и кэширует всех принципалов постранично.
func (s *storeSource) loadPrincipals(ctx context.Context) error {
	if s.princLoaded {
		return nil
	}
	offset := 0
	for {
		items, err := s.principals.List(ctx, s.q, principalPageSize, offset)
		if err != nil {
			return fmt.Errorf("accessmanifest: load principals: %w", err)
		}
		for i := range items {
			s.princList = append(s.princList, items[i].Principal)
		}
		if len(items) < principalPageSize {
			break
		}
		offset += principalPageSize
	}
	s.princLoaded = true
	return nil
}

// permissions лениво вычитывает и кэширует permissions подключения.
func (s *storeSource) permissions(ctx context.Context, connectionID uuid.UUID) ([]inventory.Permission, error) {
	if s.permCache == nil {
		s.permCache = map[uuid.UUID][]inventory.Permission{}
	}
	if cached, ok := s.permCache[connectionID]; ok {
		return cached, nil
	}
	perms, err := s.inventory.ListPermissions(ctx, s.q, connectionID)
	if err != nil {
		return nil, fmt.Errorf("accessmanifest: list permissions: %w", err)
	}
	s.permCache[connectionID] = perms
	return perms, nil
}

// ResolvePrincipal резолвит principal по id (UUID), external_subject или
// display_name. external_subject имеет приоритет над display_name;
// неоднозначность и отсутствие — *ResolveError.
func (s *storeSource) ResolvePrincipal(ctx context.Context, ref string) (principals.Principal, error) {
	if id, err := uuid.Parse(ref); err == nil {
		p, err := s.principals.Get(ctx, s.q, id)
		switch {
		case errors.Is(err, principals.ErrNotFound):
			return principals.Principal{}, resolveErr("principal %q not found", ref)
		case err != nil:
			return principals.Principal{}, err
		}
		return p, nil
	}
	if err := s.loadPrincipals(ctx); err != nil {
		return principals.Principal{}, err
	}
	var bySubject, byName []principals.Principal
	for i := range s.princList {
		if s.princList[i].ExternalSubject == ref {
			bySubject = append(bySubject, s.princList[i])
		}
		if s.princList[i].DisplayName == ref {
			byName = append(byName, s.princList[i])
		}
	}
	switch {
	case len(bySubject) == 1:
		return bySubject[0], nil
	case len(bySubject) > 1:
		return principals.Principal{}, resolveErr("principal external_subject %q is ambiguous (%d matches)", ref, len(bySubject))
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return principals.Principal{}, resolveErr("principal %q not found", ref)
	default:
		return principals.Principal{}, resolveErr("principal %q is ambiguous (%d matches by display name)", ref, len(byName))
	}
}

// ResolveConnection резолвит connection по id (UUID) или display_name.
// Неоднозначное display_name и отсутствие — *ResolveError.
func (s *storeSource) ResolveConnection(ctx context.Context, ref string) (connections.Connection, error) {
	if id, err := uuid.Parse(ref); err == nil {
		conn, err := s.connections.Get(ctx, s.q, id)
		switch {
		case errors.Is(err, connections.ErrNotFound):
			return connections.Connection{}, resolveErr("connection %q not found", ref)
		case err != nil:
			return connections.Connection{}, err
		}
		return conn, nil
	}
	if err := s.loadConnections(ctx); err != nil {
		return connections.Connection{}, err
	}
	var matches []connections.Connection
	for i := range s.connList {
		if s.connList[i].DisplayName == ref {
			matches = append(matches, s.connList[i])
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return connections.Connection{}, resolveErr("connection %q not found", ref)
	default:
		return connections.Connection{}, resolveErr("connection %q is ambiguous (%d matches)", ref, len(matches))
	}
}

// ResolvePermission резолвит permission подключения по external_id (уникален
// в рамках подключения) или name. Неоднозначное name и отсутствие —
// *ResolveError.
func (s *storeSource) ResolvePermission(ctx context.Context, connectionID uuid.UUID, ref string) (inventory.Permission, error) {
	perms, err := s.permissions(ctx, connectionID)
	if err != nil {
		return inventory.Permission{}, err
	}
	for i := range perms {
		if perms[i].ExternalID == ref {
			return perms[i], nil
		}
	}
	var byName []inventory.Permission
	for i := range perms {
		if perms[i].Name == ref {
			byName = append(byName, perms[i])
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return inventory.Permission{}, resolveErr("role %q not found in connection %s", ref, connectionID)
	default:
		return inventory.Permission{}, resolveErr("role %q is ambiguous in connection %s (%d matches by name)", ref, connectionID, len(byName))
	}
}

// Principal загружает принципала по id.
func (s *storeSource) Principal(ctx context.Context, id uuid.UUID) (principals.Principal, error) {
	return s.principals.Get(ctx, s.q, id)
}

// Connection загружает подключение по id.
func (s *storeSource) Connection(ctx context.Context, id uuid.UUID) (connections.Connection, error) {
	return s.connections.Get(ctx, s.q, id)
}

// Permission загружает permission по id.
func (s *storeSource) Permission(ctx context.Context, id uuid.UUID) (inventory.Permission, error) {
	return s.inventory.GetPermission(ctx, s.q, id)
}

// ManagedAccount ищет managed-аккаунт принципала в подключении по engine
// identity. Занятая unmanaged/deleted-identity или аккаунт другого
// принципала — Conflict (не Found): apply link/adopt делает отдельно.
func (s *storeSource) ManagedAccount(ctx context.Context, connectionID, principalID uuid.UUID, identity string) (AccountLookup, error) {
	acct, err := s.inventory.FindAccountByIdentity(ctx, s.q, connectionID, identity)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		// Identity выводится из имени принципала, но аккаунт мог быть создан
		// с явным engine_identity: тогда доступ у принципала есть, а по
		// выведенной identity он не находится, и план предлагал бы завести
		// второй аккаунт вместо того, чтобы увидеть первый.
		return s.linkedAccount(ctx, connectionID, principalID)
	case err != nil:
		return AccountLookup{}, err
	}
	if acct.Ownership != inventory.OwnershipManaged || acct.Status == inventory.AccountDeleted {
		return AccountLookup{Conflict: true, ConflictReason: inventory.IdentityConflictReason(
			identity, connectionID, acct, s.connectionSupportsRestore(ctx, connectionID))}, nil
	}
	if acct.PrincipalID == nil || *acct.PrincipalID != principalID {
		return AccountLookup{Conflict: true, ConflictReason: fmt.Sprintf(
			"identity %q in connection %s is owned by another principal", identity, connectionID)}, nil
	}
	return AccountLookup{Account: acct, Found: true}, nil
}

// linkedAccount ищет managed-аккаунт принципала в подключении, не полагаясь
// на identity: так план видит аккаунты, созданные с явным engine_identity.
//
// Несколько живых managed-аккаунтов одного принципала в одном подключении
// возможны (link/adopt нескольких учёток) и однозначного ответа не дают:
// выбор «какой-нибудь» выдал бы права не той учётке, поэтому это Conflict с
// явной причиной, а не молчаливая догадка.
func (s *storeSource) linkedAccount(ctx context.Context, connectionID, principalID uuid.UUID) (AccountLookup, error) {
	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.q, principalID)
	if err != nil {
		return AccountLookup{}, err
	}
	var found []inventory.Account
	for i := range accounts {
		acct := accounts[i]
		if acct.ConnectionID != connectionID || acct.Ownership != inventory.OwnershipManaged {
			continue
		}
		if acct.Status == inventory.AccountDeleted {
			continue
		}
		found = append(found, acct)
	}
	switch len(found) {
	case 0:
		return AccountLookup{}, nil
	case 1:
		return AccountLookup{Account: found[0], Found: true}, nil
	default:
		identities := make([]string, 0, len(found))
		for i := range found {
			identities = append(identities, found[i].EngineIdentity)
		}
		return AccountLookup{Conflict: true, ConflictReason: fmt.Sprintf(
			"principal has %d managed accounts in connection %s (%s): resolve the manifest entry manually",
			len(found), connectionID, strings.Join(identities, ", "))}, nil
	}
}

// connectionSupportsRestore сообщает, объявляет ли подключение capability
// account.restore. Вызывается только в ветке конфликта identity — ради текста
// ошибки, поэтому недоступное подключение трактуется как «restore не
// поддерживается»: сообщение станет консервативнее, но резолв не упадёт.
func (s *storeSource) connectionSupportsRestore(ctx context.Context, connectionID uuid.UUID) bool {
	conn, err := s.connections.Get(ctx, s.q, connectionID)
	if err != nil {
		return false
	}
	return slices.Contains(conn.Capabilities, string(adapter.CapAccountRestore))
}

// AccountBindings возвращает bindings аккаунта.
func (s *storeSource) AccountBindings(ctx context.Context, accountID uuid.UUID) ([]inventory.Binding, error) {
	return s.inventory.ListBindingsByAccount(ctx, s.q, accountID)
}

// PrincipalAccounts возвращает не-deleted аккаунты принципала.
func (s *storeSource) PrincipalAccounts(ctx context.Context, principalID uuid.UUID) ([]inventory.Account, error) {
	return s.inventory.ListAccountsByPrincipal(ctx, s.q, principalID)
}

// Connections возвращает все подключения (кэш загрузки).
func (s *storeSource) Connections(ctx context.Context) ([]connections.Connection, error) {
	if err := s.loadConnections(ctx); err != nil {
		return nil, err
	}
	return s.connList, nil
}

// ConnectionAccounts возвращает аккаунты подключения.
func (s *storeSource) ConnectionAccounts(ctx context.Context, connectionID uuid.UUID) ([]inventory.Account, error) {
	return s.inventory.ListAccounts(ctx, s.q, connectionID)
}
