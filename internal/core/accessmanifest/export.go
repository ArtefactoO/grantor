package accessmanifest

// Export выгружает текущее managed-состояние доступов как манифест: обратная
// операция к apply. Экспортируются только managed present bindings в
// собственной области их permission-определения (см.
// inventory.EffectiveBindingScope) на managed-аккаунтах, привязанных к
// принципалу; bindings, суженные оператором до чужого ресурса, вне модели
// манифеста. Аккаунты без principal_id пропускаются: их нельзя выразить как
// principal-запись манифеста. Порядок записей детерминирован.

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// Export выгружает текущее managed-состояние доступов как манифест. Пустой
// environment — без фильтра; иначе выгружаются только подключения этого
// окружения. connectionID (uuid.Nil — без фильтра) сужает выгрузку до одного
// подключения; environment и connectionID комбинируются. Результат готов к
// повторному apply.
func (p Planner) Export(ctx context.Context, q Querier, environment string, connectionID uuid.UUID) (Manifest, error) {
	return computeExport(ctx, p.source(q), environment, connectionID)
}

// computeExport — чистая логика экспорта поверх Source. Тестируется на
// фейковом Source без БД. environment и connectionID — необязательные фильтры
// (пустая строка / uuid.Nil — без фильтра), действующие совместно.
func computeExport(ctx context.Context, src Source, environment string, connectionID uuid.UUID) (Manifest, error) {
	conns, err := src.Connections(ctx)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Version: Version, Environment: environment, Entries: []Entry{}}

	for ci := range conns {
		conn := conns[ci]
		if environment != "" && conn.Environment != environment {
			continue
		}
		if connectionID != uuid.Nil && conn.ID != connectionID {
			continue
		}
		accounts, err := src.ConnectionAccounts(ctx, conn.ID)
		if err != nil {
			return Manifest{}, err
		}
		for ai := range accounts {
			acct := accounts[ai]
			if acct.Ownership != inventory.OwnershipManaged || acct.Status == inventory.AccountDeleted || acct.PrincipalID == nil {
				continue
			}
			principal, err := src.Principal(ctx, *acct.PrincipalID)
			if err != nil {
				return Manifest{}, err
			}
			bindings, err := src.AccountBindings(ctx, acct.ID)
			if err != nil {
				return Manifest{}, err
			}
			for bi := range bindings {
				b := bindings[bi]
				if !isManagedPresent(b) {
					continue
				}
				perm, err := src.Permission(ctx, b.PermissionDefinitionID)
				if err != nil {
					return Manifest{}, err
				}
				// Симметрия с plan/apply: экспортируется binding в собственной
				// области permission — ровно то, что apply создаст обратно.
				if !inventory.BindingHasPermissionScope(b, perm) {
					continue
				}
				m.Entries = append(m.Entries, Entry{
					Principal:  principalRef(principal),
					Connection: conn.DisplayName,
					Role:       perm.ExternalID,
					State:      string(StatePresent),
				})
			}
		}
	}

	slices.SortFunc(m.Entries, func(a, b Entry) int {
		if c := strings.Compare(a.Principal, b.Principal); c != 0 {
			return c
		}
		if c := strings.Compare(a.Connection, b.Connection); c != 0 {
			return c
		}
		return strings.Compare(a.Role, b.Role)
	})
	// Запись манифеста адресует принципала, а не аккаунт: у одного принципала
	// на одном подключении бывает несколько managed-аккаунтов (общий секрет
	// окружения и персональный), и каждый давал СВОЮ копию одной и той же
	// строки. Манифест от этого не менялся по смыслу, но переставал быть
	// стабильным при round-trip: export -> apply -> export давал другое число
	// записей, и сравнение двух выгрузок в git показывало ложную разницу.
	m.Entries = slices.Compact(m.Entries)
	return m, nil
}
