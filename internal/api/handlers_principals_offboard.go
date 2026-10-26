package api

// Обратимый offboarding принципала (уровень 2 каскада): доступ
// закрывается немедленно, но ничего не уничтожается до истечения срока
// хранения.
//
// Раньше offboard был необратим в момент нажатия — аккаунты удалялись в
// целевых системах, а общие секреты уничтожались в Vault. Промах по строке
// стоил столько же, сколько осознанное решение, а возврат человека требовал
// четырёх ручных admin-вызовов и заводил НОВОГО принципала.
//
// Теперь один bulk parent (bulk.principal_offboard) отзывает доступы
// (access.revoke) по всем managed-аккаунтам — одинаково для всех движков.
// Отзыв выбран единственным действием сознательно: обратимое выключение
// учётной записи умеют не все движки (mongodb не умеет вовсе, kafka теряет
// его без ACL-авторизатора), и развилка «где выключаем, где отзываем»
// давала частичное восстановление. Отзыв не удаляет строки bindings, а
// ставит desired=absent, поэтому восстановление перевыдаёт ровно те же
// права.
//
// Вместе с отзывом ротируются пароли: отзыв снимает права, но учётная
// запись остаётся способной аутентифицироваться со старым паролем, который
// человек знает. Новый пароль никому не выдаётся, поэтому вход закрывается
// тоже. Секрет при этом НЕ помечается удалённым: дети credential.rotate
// читают его из Vault, а pending_purge и так запрещает share.
//
// Ротация покрывает обе топологии credential: общий секрет окружения (одна
// новая версия на окружение) и личный пароль аккаунта. Исключение —
// аккаунт, чьим паролем grantor не владеет: учётку приняли под управление
// без пароля, настоящий знает владелец целевой системы, и сменить его молча
// значит присвоить чужой. Такие аккаунты по умолчанию пропускаются и
// перечисляются в ответе; ротация возможна по явному
// takeover_credentials.
//
// Ротация НЕ проходит через mass-revoke gate, в отличие от отзывов: гейт
// защищает от массового снятия прав вторым админом, а смена пароля прав не
// снимает. Ждать второго человека, оставив выводимому рабочий пароль и все
// его роли, было бы ровно тем, от чего offboard защищает.
//
// Принципал переходит в pending_purge с purge_after; необратимое
// уничтожение выполняет фоновая задача обслуживания по истечении срока.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/approval"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// auditActionPrincipalOffboarded — audit-действие вывода из системы.
const auditActionPrincipalOffboarded = "principal.offboarded"

// offboardUnmanagedAccount — привязанный unmanaged-аккаунт в ответе
// offboard: он НЕ трогается (его lifecycle принадлежит целевой системе) и
// перечисляется для ручного внимания оператора.
type offboardUnmanagedAccount struct {
	ConnectionID   uuid.UUID `json:"connection_id"`
	EngineIdentity string    `json:"engine_identity"`
}

// offboardChild — дочерняя операция offboard в ответе: access.revoke с
// binding_id отозванного права.
type offboardChild struct {
	Kind         string     `json:"kind"`
	ConnectionID uuid.UUID  `json:"connection_id"`
	AccountID    uuid.UUID  `json:"account_id"`
	BindingID    *uuid.UUID `json:"binding_id,omitempty"`
	OperationID  uuid.UUID  `json:"operation_id"`
	// Status — pending (сразу в очередь) или pending_approval (offboard
	// превысил GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD и ждёт approve).
	Status operations.Status `json:"status"`
}

// offboardAccountPlan — план offboard одного managed-аккаунта: bindings к
// отзыву у этого аккаунта.
type offboardAccountPlan struct {
	account inventory.Account
	revokes []inventory.Binding
}

// partitionOffboardAccounts делит аккаунты принципала на managed (подлежат
// отзыву доступов) и unmanaged (не трогаются, попадают в ответ для ручного
// внимания). Deleted-строки сюда не приходят (ListAccountsByPrincipal их
// не возвращает). Чистая функция для юнит-тестов.
func partitionOffboardAccounts(accounts []inventory.Account) ([]inventory.Account, []offboardUnmanagedAccount) {
	managed := make([]inventory.Account, 0, len(accounts))
	unmanaged := make([]offboardUnmanagedAccount, 0)
	for i := range accounts {
		acct := accounts[i]
		if acct.Ownership == inventory.OwnershipManaged {
			managed = append(managed, acct)
			continue
		}
		unmanaged = append(unmanaged, offboardUnmanagedAccount{
			ConnectionID:   acct.ConnectionID,
			EngineIdentity: acct.EngineIdentity,
		})
	}
	return managed, unmanaged
}

// offboardRevokeBindings отбирает managed-present bindings аккаунта — ровно
// их отзывает offboard. Unmanaged bindings (desired IS NULL) не трогаются:
// их lifecycle принадлежит целевой системе. Уже desired=absent
// пропускаются — их отзыв запрошен раньше и к этому offboard отношения не
// имеет, поэтому отмена их не вернёт. Чистая функция для юнит-тестов.
func offboardRevokeBindings(bindings []inventory.Binding) []inventory.Binding {
	out := make([]inventory.Binding, 0, len(bindings))
	for i := range bindings {
		b := bindings[i]
		if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			continue
		}
		out = append(out, b)
	}
	return out
}

// offboardOptions — разобранные параметры offboard.
type offboardOptions struct {
	// Confirm — подтверждение самого вывода из системы.
	Confirm bool
	// Takeover — согласие принять под управление пароли, которыми grantor
	// не владеет, и отротировать их вместе с остальными (см.
	// offboardRotateOwnCredentials). Только из тела: у query-параметров нет
	// места объяснить последствие, а по умолчанию такие аккаунты
	// пропускаются и перечисляются в ответе.
	Takeover bool
}

// parseOffboardOptions извлекает параметры offboard: подтверждение — из
// query-параметра confirm=true (идиома DELETE /accounts/{id}) либо из
// JSON-тела {"confirm":true} (идиома manifest apply), takeover — только из
// тела. Тело необязательно; пустое — не ошибка. Возвращает ошибку на
// нечитаемое тело.
func parseOffboardOptions(r *http.Request, body []byte) (offboardOptions, error) {
	out := offboardOptions{Confirm: r.URL.Query().Get("confirm") == "true"}
	if len(body) == 0 {
		return out, nil
	}
	var req struct {
		Confirm             bool `json:"confirm"`
		TakeoverCredentials bool `json:"takeover_credentials"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return offboardOptions{}, errors.New("invalid JSON body")
	}
	out.Confirm = out.Confirm || req.Confirm
	out.Takeover = req.TakeoverCredentials
	return out, nil
}

// offboardRotateCredentials меняет общие пароли окружений принципала на
// новые случайные и ставит детей credential.rotate по его аккаунтам. Новый
// пароль никому не выдаётся: pending_purge блокирует share, а вывод из
// системы тем самым закрывает и аутентификацию, а не только права.
//
// Аккаунты приходят УЖЕ зарезервированными: тот же аккаунт получает от
// offboard и revoke, и rotate, а второй резерв lifecycle обесценил бы
// операции, поставленные первыми (см. reserveRotationAccounts).
//
// Best-effort по составу: здесь ротируются только аккаунты, реально сидящие
// на общем секрете принципала (тот же предикат, что у обычной ротации);
// личные пароли обрабатывает offboardRotateOwnCredentials.
func (s *Server) offboardRotateCredentials(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	sess auth.Session, p principals.Principal, reserved []inventory.Account,
	parentID *uuid.UUID) ([]offboardChild, bool) {
	byEnv, envOrder, ok := s.groupRotatablePrincipalAccounts(w, r, sess, reserved, "")
	if !ok {
		return nil, false
	}
	out := make([]offboardChild, 0)
	for _, env := range envOrder {
		children, ok := s.rotatePrincipalEnvChildren(w, r, tx, sess, p, env, byEnv[env], parentID)
		if !ok {
			return nil, false
		}
		for i := range children {
			out = append(out, offboardChild{
				Kind:         jobs.KindCredentialRotate,
				ConnectionID: children[i].ConnectionID,
				AccountID:    children[i].AccountID,
				OperationID:  children[i].OperationID,
				Status:       operations.StatusPending,
			})
		}
	}
	return out, true
}

// accountOnOwnCredential — managed-аккаунт с ЛИЧНЫМ паролем: живой носитель
// credential, не сидящий на общем секрете своего принципала. Дополнение
// accountRotatableOnSharedCredential до всех ротируемых аккаунтов: вместе
// эти два предиката покрывают managed+active носителей credential без
// пересечения. Чистая функция для юнит-тестов.
//
// Сюда же попадает аккаунт с указателем в раздел ЧУЖОГО принципала: общего
// секрета ЭТОГО принципала у него нет, а per-account ротация — штатный
// способ починить такой указатель.
func accountOnOwnCredential(a inventory.Account) bool {
	return a.Ownership == inventory.OwnershipManaged &&
		a.Status == inventory.AccountActive &&
		inventory.AccountHoldsCredential(a) &&
		!accountSharesPrincipalCredential(a)
}

// offboardOwnCredentials делит аккаунты с личным паролем на две группы по
// факту в Vault: owned — пароль лежит в accounts/<id>/credential и им
// владеет grantor, unowned — секрета нет, то есть учётку приняли под
// управление без пароля (adopt mode=metadata) и настоящий пароль знает
// только владелец целевой системы.
//
// Различие проводится по Vault, а не по account.vault_path: поле хранит
// намерение control plane и может расходиться с содержимым хранилища.
// Ошибка Vault пробрасывается вызывающему: временная недоступность не
// должна тихо превращаться в «пароля нет» и уводить аккаунт не в ту группу.
func (s *Server) offboardOwnCredentials(ctx context.Context, managed []inventory.Account) (owned, unowned []inventory.Account, err error) {
	owned = make([]inventory.Account, 0)
	unowned = make([]inventory.Account, 0)
	for i := range managed {
		if !accountOnOwnCredential(managed[i]) {
			continue
		}
		exists, err := s.credentials.OwnAccountCredentialExists(ctx, managed[i].ID)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			owned = append(owned, managed[i])
			continue
		}
		unowned = append(unowned, managed[i])
	}
	return owned, unowned, nil
}

// offboardRotateOwnCredentials ставит по одной credential.rotate на каждый
// аккаунт с личным паролем. SharedCredentialPath в payload не передаётся,
// поэтому executor генерирует новый пароль сам (rotateSourceGenerate) и
// пишет его в accounts/<id>/credential — в отличие от общего секрета, где
// новую версию заранее записывает API-слой.
//
// Аккаунты, чьим паролем grantor не владеет, попадают сюда только по явному
// takeover_credentials: ротация присвоила бы grantor пароль, которым
// управляет владелец целевой системы, и сделать это молча нельзя.
//
// Аккаунты обязаны быть уже зарезервированы вызывающим — по той же причине,
// что и у ротации общего секрета (см. reserveRotationAccounts).
func (s *Server) offboardRotateOwnCredentials(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	sess auth.Session, accts []inventory.Account, parentID *uuid.UUID) ([]offboardChild, bool) {
	ctx := r.Context()
	out := make([]offboardChild, 0, len(accts))
	for i := range accts {
		reserved := accts[i]
		if err := s.checkConnectionScopeByID(ctx, sess, reserved.ConnectionID); err != nil {
			s.respondScopeError(ctx, w, err)
			return nil, false
		}
		payload, err := json.Marshal(jobs.AccountPayload{
			AccountID: reserved.ID, ExpectedStatus: reserved.Status,
			ExpectedLifecycleVersion: reserved.LifecycleVersion,
		})
		if err != nil {
			respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
			return nil, false
		}
		op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
			Kind:          jobs.KindCredentialRotate,
			ParentID:      parentID,
			ConnectionID:  &reserved.ConnectionID,
			AccountID:     &reserved.ID,
			PrincipalID:   reserved.PrincipalID,
			Payload:       payload,
			ActorType:     sess.ActorType(),
			ActorID:       sess.ActorID(),
			CorrelationID: uuid.NewString(),
		})
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, false
		}
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			respondStoreError(ctx, w, err)
			return nil, false
		}
		out = append(out, offboardChild{
			Kind:         jobs.KindCredentialRotate,
			ConnectionID: reserved.ConnectionID,
			AccountID:    reserved.ID,
			OperationID:  op.ID,
			Status:       op.Status,
		})
	}
	return out, true
}

// accountsByID отбирает из reserved строки тех же аккаунтов, что и в want,
// сохраняя порядок want. Нужен каскаду: состав групп считается до
// транзакции по прочитанным строкам, а операции обязаны нести версию
// lifecycle из резерва внутри неё. Аккаунт, которого в reserved нет,
// пропускается: он не резервировался, значит и операций ему не ставят.
func accountsByID(reserved, want []inventory.Account) []inventory.Account {
	byID := make(map[uuid.UUID]inventory.Account, len(reserved))
	for i := range reserved {
		byID[reserved[i].ID] = reserved[i]
	}
	out := make([]inventory.Account, 0, len(want))
	for i := range want {
		if acct, ok := byID[want[i].ID]; ok {
			out = append(out, acct)
		}
	}
	return out
}

// offboardEnvironmentsAndConnections собирает по managed- и
// unmanaged-аккаунтам принципала окружения его подключений (для зачистки
// общих секретов) и id подключений managed-аккаунтов (для audit). Оба
// списка дедуплицированы в порядке первого появления.
func (s *Server) offboardEnvironmentsAndConnections(ctx context.Context, accounts, managed []inventory.Account) ([]string, []uuid.UUID, error) {
	envByConn := map[uuid.UUID]string{}
	envs := make([]string, 0)
	seenEnv := map[string]bool{}
	for i := range accounts {
		connID := accounts[i].ConnectionID
		env, ok := envByConn[connID]
		if !ok {
			conn, err := s.connections.Get(ctx, s.pool, connID)
			if err != nil {
				return nil, nil, err
			}
			env = environmentOf(conn)
			envByConn[connID] = env
		}
		if !seenEnv[env] {
			seenEnv[env] = true
			envs = append(envs, env)
		}
	}
	// Credential может быть подготовлен до появления аккаунта. Поэтому
	// offboard обязан зачистить не только окружения связанных аккаунтов, но
	// и все окружения, которые сейчас существуют в подключениях.
	conns, err := s.connections.List(ctx, s.pool)
	if err != nil {
		return nil, nil, err
	}
	for i := range conns {
		env := environmentOf(conns[i])
		if !seenEnv[env] {
			seenEnv[env] = true
			envs = append(envs, env)
		}
	}
	connIDs := make([]uuid.UUID, 0, len(managed))
	seenConn := map[uuid.UUID]bool{}
	for i := range managed {
		if connID := managed[i].ConnectionID; !seenConn[connID] {
			seenConn[connID] = true
			connIDs = append(connIDs, connID)
		}
	}
	return envs, connIDs, nil
}

// offboardPrincipal — POST /api/v1/principals/{id}/offboard?confirm=true
// (admin): обратимый offboarding. Один bulk parent
// (bulk.principal_offboard) с детьми по каждому managed-аккаунту:
// access.revoke его managed-present bindings и credential.rotate его
// пароля. Отзывов больше GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD — дети
// создаются в pending_approval и ждут approve-children. Принципал
// переходит в pending_purge с purge_after = now + срок хранения; ничего не
// уничтожается, необратимое удаление выполняет обслуживание по истечении
// срока.
//
// Ротация покрывает обе топологии credential: общий секрет окружения (одна
// новая версия на окружение) и личные пароли аккаунтов. Личный пароль,
// которым grantor не владеет, по умолчанию не трогается и перечисляется в
// ответе как credential_takeover_required — отротировать его можно явным
// {"takeover_credentials":true}.
//
// Unmanaged-аккаунты не трогаются и перечисляются в ответе. Повторный
// offboard — 409. Без managed-аккаунтов — metadata-only переход (200), bulk
// parent не создаётся.
func (s *Server) offboardPrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	opts, err := parseOffboardOptions(r, body)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !opts.Confirm {
		respondError(w, http.StatusBadRequest, "principal offboarding requires confirm=true")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	p, err := s.principals.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if p.Status == principals.StatusDeleted {
		respondError(w, http.StatusConflict, "principal is already offboarded")
		return
	}
	if p.Status == principals.StatusPendingPurge {
		respondError(w, http.StatusConflict, "principal is already being offboarded")
		return
	}

	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	managed, unmanaged := partitionOffboardAccounts(accounts)
	envs, connIDs, err := s.offboardEnvironmentsAndConnections(ctx, accounts, managed)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	plans := make([]offboardAccountPlan, 0, len(managed))
	totalRevokes := 0
	for i := range managed {
		bindings, err := s.inventory.ListBindingsByAccount(ctx, s.pool, managed[i].ID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		revokes := offboardRevokeBindings(bindings)
		totalRevokes += len(revokes)
		plans = append(plans, offboardAccountPlan{account: managed[i], revokes: revokes})
	}
	auditMeta := map[string]any{
		"managed_accounts": len(managed),
		"revoked_bindings": totalRevokes,
		"connections":      connIDs,
		"unmanaged_linked": len(unmanaged),
	}

	if len(managed) == 0 {
		s.offboardMetadataOnly(w, r, sess, p, envs, unmanaged, auditMeta)
		return
	}

	for _, account := range managed {
		conn, loadErr := s.connections.Get(ctx, s.pool, account.ConnectionID)
		if loadErr != nil {
			respondStoreError(ctx, w, loadErr)
			return
		}
		if conn.AuthMode == "none" {
			respondError(w, http.StatusConflict, "authentication_disabled: principal offboarding requires a password connection")
			return
		}
	}
	// Классификация личных паролей идёт до транзакции: она ходит в Vault, а
	// держать сетевые вызовы внутри открытой транзакции значит удлинять её
	// блокировки на время чужого таймаута.
	ownedCreds, unownedCreds, err := s.offboardOwnCredentials(ctx, managed)
	if err != nil {
		if errors.Is(err, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot offboard principal; set GRANTOR_VAULT_ADDR")
			return
		}
		slog.ErrorContext(ctx, "api: classify principal own credentials",
			"principal_id", p.ID, "error", err)
		respondError(w, http.StatusBadGateway, "failed to inspect account credentials in vault")
		return
	}
	rotateOwn := ownedCreds
	if opts.Takeover {
		rotateOwn = append(append(make([]inventory.Account, 0, len(ownedCreds)+len(unownedCreds)),
			ownedCreds...), unownedCreds...)
	}
	auditMeta["takeover_credentials"] = opts.Takeover
	// Отчёт о пропущенных обязателен даже при takeover (тогда список пуст):
	// «сколько паролей мы НЕ закрыли» — часть результата вывода из системы,
	// а не деталь реализации.
	skipped := make([]offboardUnmanagedAccount, 0)
	if !opts.Takeover {
		for i := range unownedCreds {
			skipped = append(skipped, offboardUnmanagedAccount{
				ConnectionID:   unownedCreds[i].ConnectionID,
				EngineIdentity: unownedCreds[i].EngineIdentity,
			})
		}
	}
	auditMeta["credential_takeover_required"] = len(skipped)

	s.runBulkParent(w, r, sess, bulkParent{
		kind:        jobs.KindBulkPrincipalOffboard,
		principalID: &p.ID,
		payload: map[string]any{
			"selection": "managed_accounts_request_snapshot",
			"confirmed": true,
		},
		payloadErrPrefix: "api: marshal principal offboard payload",
		auditAction:      auditActionPrincipalOffboarded,
		commitErrPrefix:  "api: commit principal offboard",
		extraResponse: map[string]any{
			"unmanaged_accounts":           unmanaged,
			"credential_takeover_required": skipped,
		},
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		if !s.lockCredentialConnections(w, r, tx, managed, "") {
			return nil, nil, false
		}
		// Metadata-adopted unowned credentials are deliberately skipped unless
		// takeover was requested. Only actual password targets require rotate.
		rotateTargets := append([]inventory.Account(nil), rotateOwn...)
		for _, account := range managed {
			if accountRotatableOnSharedCredential(account) {
				rotateTargets = append(rotateTargets, account)
			}
		}
		for _, account := range rotateTargets {
			conn, err := s.connections.Get(ctx, tx, account.ConnectionID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			if err := requireConnectionCapability(conn, adapter.CapCredentialRotate); err != nil {
				respondError(w, http.StatusConflict, err.Error())
				return nil, nil, false
			}
		}
		if _, err := s.principals.SetStatus(ctx, tx, p.ID, principals.StatusPendingPurge); err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		purgeAfter := time.Now().Add(s.purgeRetention)
		if _, err := s.principals.SetPurgeAfter(ctx, tx, p.ID, &purgeAfter); err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		auditMeta["purge_after"] = purgeAfter.UTC().Format(time.RFC3339)
		// Rebuild the revoke plan only after every account row is reserved.
		// A concurrent grant that committed first is included; a grant that
		// starts later waits for this transaction and then sees lifecycle busy.
		txPlans := make([]offboardAccountPlan, 0, len(plans))
		txRevokes := 0
		for i := range plans {
			plan := plans[i]
			// Reserve delete incarnation before enqueueing revoke children. Both
			// kinds then pin the same generation: revoke may run first, or may
			// converge as a guarded no-op after delete removed bindings.
			reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, plan.account.ID, plan.account.Status)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			plan.account = reserved
			bindings, err := s.inventory.ListBindingsByAccount(ctx, tx, plan.account.ID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			plan.revokes = offboardRevokeBindings(bindings)
			txRevokes += len(plan.revokes)
			txPlans = append(txPlans, plan)
		}
		requiresApproval := approval.RequiresMassRevoke(s.massRevokeThreshold, txRevokes)
		auditMeta["revoked_bindings"] = txRevokes
		out := make([]offboardChild, 0, len(txPlans)+txRevokes)
		for i := range txPlans {
			plan := txPlans[i]
			for j := range plan.revokes {
				op, err := s.createRevoke(r, tx, sess, plan.revokes[j], plan.account, &parentID, requiresApproval)
				if err != nil {
					respondStoreError(ctx, w, err)
					return nil, nil, false
				}
				bindingID := plan.revokes[j].ID
				out = append(out, offboardChild{
					Kind:         op.Kind,
					ConnectionID: plan.account.ConnectionID,
					AccountID:    plan.account.ID,
					BindingID:    &bindingID,
					OperationID:  op.ID,
					Status:       op.Status,
				})
			}
		}

		// Пароль меняется на новый случайный, который никому не выдаётся:
		// отзыв снимает права, но вход по известному человеку паролю без
		// этого остаётся открытым.
		//
		// Резерв lifecycle уже сделан выше, по одному на аккаунт: revoke и
		// rotate одного аккаунта обязаны пинить одно поколение, иначе
		// поставленный первым revoke упадёт с lifecycle conflict.
		reservedManaged := make([]inventory.Account, 0, len(txPlans))
		for i := range txPlans {
			reservedManaged = append(reservedManaged, txPlans[i].account)
		}
		rotated, ok := s.offboardRotateCredentials(w, r, tx, sess, p, reservedManaged, &parentID)
		if !ok {
			return nil, nil, false
		}
		ownRotated, ok := s.offboardRotateOwnCredentials(w, r, tx, sess,
			accountsByID(reservedManaged, rotateOwn), &parentID)
		if !ok {
			return nil, nil, false
		}
		auditMeta["rotated_accounts"] = len(rotated) + len(ownRotated)
		auditMeta["rotated_own_credentials"] = len(ownRotated)
		out = append(out, rotated...)
		out = append(out, ownRotated...)
		return out, auditMeta, true
	})
}

// offboardMetadataOnly — offboard принципала без managed-аккаунтов: bulk
// parent не создаётся (детей нет), одной транзакцией пишутся переход в
// pending_purge, срок хранения и audit-событие, затем best-effort
// помечаются удалёнными общие секреты. Ответ 200: принципал и его
// unmanaged-аккаунты.
func (s *Server) offboardMetadataOnly(w http.ResponseWriter, r *http.Request, sess auth.Session,
	p principals.Principal, envs []string, unmanaged []offboardUnmanagedAccount, auditMeta map[string]any) {
	ctx := r.Context()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := s.principals.SetStatus(ctx, tx, p.ID, principals.StatusPendingPurge); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	purgeAfter := time.Now().Add(s.purgeRetention)
	updated, err := s.principals.SetPurgeAfter(ctx, tx, p.ID, &purgeAfter)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	auditMeta["purge_after"] = purgeAfter.UTC().Format(time.RFC3339)
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionPrincipalOffboarded,
		PrincipalID: &p.ID,
		Result:      audit.ResultSuccess,
	}, auditMeta); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit principal offboard: %w", err))
		return
	}
	fields, err := principalResponseFields(updated)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	fields["unmanaged_accounts"] = unmanaged
	respondJSON(w, http.StatusOK, fields)
}
