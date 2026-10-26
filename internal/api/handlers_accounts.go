package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// Audit actions мутирующих запросов accounts. credential_shared — имя из
// раздела 18 архитектуры: фиксируется факт выдачи, но не сама ссылка.
const (
	auditActionAccountCreateRequested  = "account.create_requested"
	auditActionAccountDisableRequested = "account.disable_requested"
	auditActionAccountEnableRequested  = "account.enable_requested"
	auditActionAccountDeleteRequested  = "account.delete_requested"
	auditActionAccountPurged           = "account.purged"
	auditActionAccountRestoreRequested = "account.restore_requested"
	auditActionRotateRequested         = "credential.rotate_requested"
	auditActionCredentialShared        = "credential_shared"
	// account.adopted — принятие unmanaged-аккаунта под управление в режиме
	// metadata (немедленное, без операции); account.adopt_requested —
	// постановка adopt-операции в режимах generate/set_password/
	// verify_password. Итог фиксирует worker: для generate и set_password —
	// audit actions credential.rotate с маркером adopted, для verify_password —
	// account.adopted / account.adopt_failed.
	auditActionAccountAdopted        = "account.adopted"
	auditActionAccountAdoptRequested = "account.adopt_requested"
)

// Машиночитаемые коды 409-ответов ротации. Код позволяет UI и скриптам
// отличить «нужен осознанный выбор оператора» от прочих конфликтов, не
// разбирая текст ошибки (тексты меняются, коды — контракт).
const (
	// errCodeSharedCredentialRequiresChoice — ротация аккаунта, сидящего на
	// общем секрете принципала, запрошена без явного намерения. Молча увести
	// такой аккаунт на собственный путь нельзя: инвариант ADR-0008 «один
	// пароль на пару principal+environment» ломается тихо — общий секрет
	// остаётся со старым значением, остальные аккаунты принципала живут на
	// нём, а /principals/{id}/share продолжает выдавать пароль, для
	// отротированного аккаунта уже мёртвый.
	errCodeSharedCredentialRequiresChoice = "shared_credential_requires_choice"
	// errCodeRotationRequiresConfirm — ротация общего секрета принципала
	// затрагивает больше аккаунтов, чем порог GRANTOR_ROTATION_CONFIRM_THRESHOLD,
	// и не подтверждена флагом confirm.
	errCodeRotationRequiresConfirm = "rotation_requires_confirm"
)

// Режимы credential при создании account (раздел 17.1 архитектуры;
// режимы existing_vault_ref и external_identity — вне scope этапа 1b).
// Значения — доменные константы inventory: их же пишет executor.
const (
	credentialModeGenerated = inventory.CredentialModeGenerated
	credentialModeProvided  = inventory.CredentialModeProvided
	credentialModePrincipal = inventory.CredentialModeExistingVaultRef
)

// Режимы принятия unmanaged-аккаунта под управление
// (POST /api/v1/accounts/{id}/adopt):
//
//   - metadata — только метаданные grantor, целевая система не затрагивается;
//   - generate — grantor генерирует НОВЫЙ пароль и применяет его к учётной
//     записи;
//   - set_password — оператор задаёт НОВЫЙ пароль, он применяется к учётной
//     записи (прежний пароль перестаёт работать);
//   - verify_password — оператор подтверждает СУЩЕСТВУЮЩИЙ пароль: grantor
//     доказывает его на целевой системе и принимает аккаунт, ничего на target
//     не меняя.
//
// Имена set_password и verify_password намеренно содержат глагол: прежнее имя
// password не различало «задать» и «подтвердить», и оператор, принимавший
// живую учётку с известным паролем, опечаткой молча менял пароль работающему
// приложению.
const (
	adoptModeMetadata       = "metadata"
	adoptModeGenerate       = "generate"
	adoptModeSetPassword    = "set_password"
	adoptModeVerifyPassword = "verify_password"
	// adoptModeLegacyPassword — прежнее имя режима set_password. Принимается
	// как синоним ради обратной совместимости уже существующих вызывающих;
	// канонизируется в set_password до любой обработки, поэтому дальше по коду
	// (включая audit) режимов остаётся четыре.
	adoptModeLegacyPassword = "password"
)

// shareTTLHours — TTL одноразовой ссылки Yopass в часах (раздел 18).
const shareTTLHours = 24

// Restore получает пароль только в теле запроса и немедленно переносит его
// в Vault. Ограничения защищают target adapters от пустых/неразумно больших
// значений, не нормализуя сам секрет (пробелы и Unicode остаются значимыми).
const (
	restorePasswordMinRunes = 12
	restorePasswordMaxRunes = 256
)

// accountCredentialRequest — блок credential в теле создания account.
// Password уходит только в Vault и не логируется.
type accountCredentialRequest struct {
	Mode     string `json:"mode"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// createAccountRequest — тело POST /api/v1/accounts.
type createAccountRequest struct {
	ConnectionID   uuid.UUID                 `json:"connection_id"`
	EngineIdentity string                    `json:"engine_identity"`
	PrincipalID    *uuid.UUID                `json:"principal_id"`
	Credential     *accountCredentialRequest `json:"credential"`
}

// restoreAccountRequest намеренно уже create DTO: username и identity
// выводятся из tombstone и не могут быть подменены запросом.
type restoreAccountRequest struct {
	Credential *restoreCredentialRequest `json:"credential"`
}

type restoreCredentialRequest struct {
	Mode     string `json:"mode"`
	Password string `json:"password"`
}

func (req *restoreAccountRequest) validate() error {
	if req.Credential == nil {
		return errors.New("credential is required")
	}
	switch req.Credential.Mode {
	case credentialModeGenerated:
		if req.Credential.Password != "" {
			return errors.New("credential.password must not be set for generated mode")
		}
	case credentialModeProvided:
		length := utf8.RuneCountInString(req.Credential.Password)
		if length < restorePasswordMinRunes || length > restorePasswordMaxRunes {
			return fmt.Errorf("credential.password must be between %d and %d characters", restorePasswordMinRunes, restorePasswordMaxRunes)
		}
		if strings.ContainsRune(req.Credential.Password, '\x00') {
			return errors.New("credential.password must not contain NUL")
		}
	case credentialModePrincipal:
		if req.Credential.Password != "" {
			return errors.New("credential.password must not be set for existing_vault_ref mode")
		}
	default:
		return fmt.Errorf("credential.mode must be %q, %q or %q", credentialModeGenerated, credentialModeProvided, credentialModePrincipal)
	}
	return nil
}

// validate проверяет тело создания account. Тексты ошибок уходят клиенту
// с кодом 400 и значений credential не содержат.
func (req *createAccountRequest) validate() error {
	if req.ConnectionID == uuid.Nil {
		return errors.New("connection_id is required")
	}
	if strings.TrimSpace(req.EngineIdentity) == "" {
		return errors.New("engine_identity is required")
	}
	if strings.ContainsAny(req.EngineIdentity, " \t\n") {
		return errors.New("engine_identity must not contain whitespace")
	}
	if req.Credential == nil {
		return errors.New("credential is required")
	}
	switch req.Credential.Mode {
	case credentialModeGenerated:
		if req.Credential.Password != "" {
			return errors.New("credential.password must not be set for generated mode")
		}
	case credentialModeProvided:
		if req.Credential.Password == "" {
			return errors.New("credential.password is required for provided mode")
		}
	default:
		return fmt.Errorf("credential.mode must be %q or %q", credentialModeGenerated, credentialModeProvided)
	}
	return nil
}

// createAccount — POST /api/v1/accounts (operator): создаёт managed
// account в metadata, кладёт credential в Vault и ставит операцию
// account.create для провижининга в целевой системе.
//
// Порядок в одной транзакции metadata database (как в createConnection):
// INSERT account -> Vault Put accounts/<id>/credential -> UPDATE
// vault_path -> операция + enqueue -> audit -> COMMIT. При ошибке до
// COMMIT транзакция откатывается; сиротская версия секрета в Vault при
// упавшем COMMIT безвредна (путь скоупится id, который никем не занят).
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createAccountRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	conn, err := s.connections.Get(ctx, s.pool, req.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: operator создаёт accounts только в connections своих окружений.
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection status %q does not allow account provisioning; discover the connection first", conn.Status))
		return
	}
	if conn.Engine == "postgres" {
		if postgres.ProtectedRole(req.EngineIdentity) {
			respondError(w, http.StatusBadRequest, "system PostgreSQL identities cannot be provisioned or managed")
			return
		}
		if _, err := requirePostgresProvisioningAuthority(conn, adapter.CapAccountCreate); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("engine %q is not supported by this control plane", conn.Engine))
		return
	}
	// Движок без account.create отклонил бы изменение уже в adapter: честнее
	// отказать здесь, чем писать credential в Vault и ставить обречённую
	// операцию (см. accountOperationCapability).
	if !ad.Manifest().HasCapability(adapter.CapAccountCreate) ||
		!slices.Contains(conn.Capabilities, string(adapter.CapAccountCreate)) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"%s is unavailable for engine %q of connection %s; refresh discovery and verify provisioning authority",
			adapter.CapAccountCreate, conn.Engine, conn.ID))
		return
	}

	username := req.Credential.Username
	if username == "" {
		username = req.EngineIdentity
	}
	var password []byte
	if req.Credential.Mode == credentialModeGenerated {
		generated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
		if err != nil {
			slog.ErrorContext(ctx, "api: generate credential", "connection_id", conn.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to generate credential")
			return
		}
		password = generated.Secret
	} else {
		password = []byte(req.Credential.Password)
	}
	defer clear(password)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, conn.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err = s.connections.Get(ctx, tx, conn.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := requireConnectionCapability(conn, adapter.CapAccountCreate); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	var postgresPins postgresProvisioningPins
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, adapter.CapAccountCreate)
		if err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}

	// Строка создаётся в provisioning, как и на пути выдачи доступа
	// (handlers_principal_access): живой managed-учёткой она станет только
	// после подтверждённых Apply и Verify адаптера. Сразу active означало бы,
	// что control plane утверждает существование учётки до того, как движок её
	// создал: провалившийся account.create (в том числе отказ по чужой
	// identity) оставлял бы active managed-аккаунт, попадающий в ротацию,
	// share и массовые операции принципала.
	acct, err := s.inventory.CreateProvisioningAccount(ctx, tx, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: req.EngineIdentity,
		PrincipalID:    req.PrincipalID,
		CredentialMode: req.Credential.Mode,
	})
	if err != nil {
		if errors.Is(err, inventory.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"account %q already exists in this connection", req.EngineIdentity))
			return
		}
		respondStoreError(ctx, w, err)
		return
	}

	credentialVersion, path, err := s.credentials.PutAccountCredential(ctx, acct.ID, username, password)
	if err != nil {
		if errors.Is(err, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot store account credential; set GRANTOR_VAULT_ADDR")
			return
		}
		// Ошибки vault-клиента содержат только операцию, mount и path.
		slog.ErrorContext(ctx, "api: store account credential", "account_id", acct.ID, "error", err)
		respondError(w, http.StatusBadGateway, "failed to store account credential in vault")
		return
	}
	if err := s.inventory.SetAccountVaultPath(ctx, tx, acct.ID, path); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, acct.Status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, ExpectedStatus: acct.Status,
		CredentialVaultVersion:        credentialVersion,
		ExpectedLifecycleVersion:      reserved.LifecycleVersion,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedTargetIdentity:        postgresPins.TargetIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
		return
	}
	operationKind := jobs.KindAccountCreate
	if conn.Engine == "postgres" {
		operationKind = jobs.KindPostgresAccountProvisionV1
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionAccountCreateRequested,
		ConnectionID: &conn.ID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"engine_identity": acct.EngineIdentity,
		"credential_mode": req.Credential.Mode,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create account: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id":   acct.ID,
		"operation_id": op.ID,
	})
}

// requireLoginAccount проверяет, что аккаунт вообще является носителем
// credential (kind=login), и иначе пишет 409 с указанием запрошенного
// действия. Строки group/role заводит discovery, чтобы показать членство:
// это носители ПРАВ, а не учётные записи. Credential-операции над ними
// бессмысленны (пароля у них нет и быть не может), а lifecycle-операции
// разрушительны — account.delete для PostgreSQL это DROP ROLE, то есть
// уничтожение permission-роли и каскадный отзыв доступа у всех её членов.
//
// Guard намеренно один на все ручки: до этого он был только в
// restoreAccount, и через delete/adopt/rotate/disable роль попадала под
// управление как «аккаунт». action — герундий операции ("deleted",
// "rotated"), kind не секретен и в текст ошибки попадать может.
func requireLoginAccount(w http.ResponseWriter, acct inventory.Account, action string) bool {
	if inventory.AccountHoldsCredential(acct) {
		return true
	}
	respondError(w, http.StatusConflict, fmt.Sprintf(
		"account %q has kind %q: it holds permissions and has no credential of its own; only a login account can be %s",
		acct.EngineIdentity, acct.Kind, action))
	return false
}

// requireManagedAccount загружает account и требует ownership=managed:
// lifecycle unmanaged-аккаунтов принадлежит целевой системе, их статус
// перезаписывает discovery. Дополнительно требует kind=login: lifecycle- и
// credential-операции применимы только к носителю credential (см.
// requireLoginAccount). action — герундий операции для текста ошибки. При
// ошибке пишет ответ и возвращает ok=false.
func (s *Server) requireManagedAccount(w http.ResponseWriter, r *http.Request, action string) (inventory.Account, bool) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return inventory.Account{}, false
	}
	acct, err := s.inventory.GetAccount(r.Context(), s.pool, id)
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return inventory.Account{}, false
	}
	if acct.Ownership != inventory.OwnershipManaged {
		respondError(w, http.StatusConflict, "account is not managed by grantor")
		return inventory.Account{}, false
	}
	if !requireLoginAccount(w, acct, action) {
		return inventory.Account{}, false
	}
	return acct, true
}

// accountOperationOpts — необязательные параметры enqueueAccountOperation.
// Zero value повторяет прежнее поведение lifecycle-ручек побайтово.
type accountOperationOpts struct {
	// reason — причина удаления (только account.delete; у остальных пустая —
	// omitempty сохраняет их payload побайтово).
	reason string
	// sharedCredentialPath — путь общего секрета принципала для операции
	// credential.rotate «вернуть аккаунт на общий пароль»: executor читает по
	// нему ТЕКУЩИЙ пароль и применяет к цели, не генерируя новый
	// (rotateSourceShared) — ровно как дочерние ротации принципала.
	sharedCredentialPath string
	// credentialMode — режим credential, фиксируемый в metadata в той же
	// транзакции, что и постановка операции. Нужен возврату на общий секрет:
	// executor на успехе перезапишет vault_path, а режим не трогает, и без
	// этого пара (credential_mode, vault_path) осталась бы рассогласованной.
	// До успеха операции строка остаётся на собственном пути аккаунта —
	// такая пара инертна: массовая ротация принципала её пропускает, share
	// выдаёт всё ещё рабочий собственный пароль.
	credentialMode string
	// extraResponse — дополнительные верхнеуровневые поля 202-ответа
	// (ротация добавляет vault_path и detached/attached).
	extraResponse map[string]any
}

// accountOperationCapability — capability движка, без которой lifecycle-
// операция обречена: adapter отклонит изменение как неподдерживаемое
// (adapter.ErrUnsupportedChange). Отказ детерминирован, поэтому честнее
// ответить 409 синхронно, чем создать операцию, которая всё равно упадёт
// (тот же приём — у account.restore и access.grant).
//
// API проверяет и manifest, и effective connection capabilities. Worker
// повторяет no-auth/capability guard до credential IO для уже поставленных jobs.
var accountOperationCapability = map[string]adapter.Capability{
	jobs.KindAccountDisable:   adapter.CapAccountDisable,
	jobs.KindAccountEnable:    adapter.CapAccountEnable,
	jobs.KindAccountDelete:    adapter.CapAccountDelete,
	jobs.KindCredentialRotate: adapter.CapCredentialRotate,
}

// requireEngineCapability checks the effective connection capability before
// reserving lifecycle or writing credentials. Unknown-engine behavior follows
// requireConnectionCapability; explicit no-auth is always rejected.
func (s *Server) requireEngineCapability(w http.ResponseWriter, r *http.Request, acct inventory.Account, kind string) bool {
	capability, ok := accountOperationCapability[kind]
	if !ok {
		return true
	}
	ctx := r.Context()
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return false
	}
	if err := requireConnectionCapability(conn, capability); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return false
	}
	return true
}

// enqueueAccountOperation создаёт операцию kind {account_id}, ставит её
// в очередь и пишет audit-событие в одной транзакции; отвечает 202.
func (s *Server) enqueueAccountOperation(w http.ResponseWriter, r *http.Request, acct inventory.Account,
	kind, auditAction string, opts accountOperationOpts) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	// Scope: operator трогает account только в connection своего окружения.
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	// Проверка до резервации lifecycle: отказ не должен ни двигать поколение
	// аккаунта, ни оставлять после себя операцию.
	if !s.requireEngineCapability(w, r, acct, kind) {
		return
	}
	if acct.Status == inventory.AccountProvisioning {
		respondError(w, http.StatusConflict,
			"account creation is unconfirmed; recover provisioning before changing the target account")
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	expectedStatus := acct.Status
	switch kind {
	case jobs.KindAccountDisable:
		expectedStatus = inventory.AccountActive
	case jobs.KindAccountEnable:
		expectedStatus = inventory.AccountDisabled
	case jobs.KindAccountDelete:
		// Provisioning is rejected above: a failed CREATE may have collided
		// with an existing role, so DELETE must not be used to clear its draft.
		if acct.Status == inventory.AccountDeleted {
			respondError(w, http.StatusConflict, "account is already deleted")
			return
		}
	case jobs.KindCredentialRotate:
		if acct.Status == inventory.AccountDeleted {
			respondError(w, http.StatusConflict, "deleted account credential cannot be rotated")
			return
		}
	default:
		respondStoreError(ctx, w, fmt.Errorf("api: unsupported lifecycle operation %q", kind))
		return
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, expectedStatus)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if kind == jobs.KindAccountEnable {
		if err := s.inventory.EnsureNoActiveAccessOperations(ctx, tx, acct.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if opts.credentialMode != "" {
		// vault_path не трогаем: его перезапишет executor на успехе. До тех
		// пор аккаунт живёт на собственном (рабочем) секрете.
		if _, err := s.inventory.SetAccountManaged(ctx, tx, acct.ID, "", opts.credentialMode); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, Reason: opts.reason, ExpectedStatus: expectedStatus,
		ExpectedLifecycleVersion: reserved.LifecycleVersion,
		SharedCredentialPath:     opts.sharedCredentialPath,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          kind,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	auditMeta := map[string]any{"engine_identity": acct.EngineIdentity}
	if opts.reason != "" {
		// Причина — несекретный пользовательский текст; фиксируем и в
		// audit-событии запроса, не только на успехе операции.
		auditMeta["reason"] = opts.reason
	}
	// Смена принадлежности credential — событие, которое обязано быть видно
	// в журнале: имена флагов несекретны, путь секрета в audit не пишем.
	for _, flag := range []string{"detached", "attached"} {
		if v, ok := opts.extraResponse[flag]; ok && v == true {
			auditMeta[flag] = true
		}
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditAction,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, auditMeta); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit account operation: %w", err))
		return
	}
	resp := map[string]any{
		"account_id":   acct.ID,
		"operation_id": op.ID,
	}
	for k, v := range opts.extraResponse {
		resp[k] = v
	}
	respondJSON(w, http.StatusAccepted, resp)
}

// disableAccount — POST /api/v1/accounts/{id}/disable (operator).
func (s *Server) disableAccount(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.requireManagedAccount(w, r, "disabled")
	if !ok {
		return
	}
	s.enqueueAccountOperation(w, r, acct, jobs.KindAccountDisable, auditActionAccountDisableRequested, accountOperationOpts{})
}

// enableAccount — POST /api/v1/accounts/{id}/enable (operator).
func (s *Server) enableAccount(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.requireManagedAccount(w, r, "enabled")
	if !ok {
		return
	}
	s.enqueueAccountOperation(w, r, acct, jobs.KindAccountEnable, auditActionAccountEnableRequested, accountOperationOpts{})
}

// deleteReasonMaxLen — предел длины причины удаления аккаунта в символах
// (runes): свободный текст оператора, не секрет.
const deleteReasonMaxLen = 500

// normalizeDeleteReason валидирует причину удаления: обрезает пробельные
// края и ограничивает длину; пустая строка после trim — «без причины»
// (в БД станет NULL). Текст ошибки уходит клиенту с кодом 400.
func normalizeDeleteReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if utf8.RuneCountInString(reason) > deleteReasonMaxLen {
		return "", fmt.Errorf("reason must be at most %d characters", deleteReasonMaxLen)
	}
	return reason, nil
}

// deleteAccountRequest — необязательное JSON-тело DELETE /accounts/{id}:
// причина удаления. Подтверждение остаётся query-параметром confirm=true
// (идиома деструктивных DELETE, как ?force=true у connection), а
// свободный текст идёт телом — как body-идиома offboardConfirmed — чтобы
// пользовательский текст не попадал в URL и access-логи.
type deleteAccountRequest struct {
	Reason string `json:"reason"`
}

// deleteAccount — DELETE /api/v1/accounts/{id}?confirm=true (admin):
// удаление учётной записи в целевой системе и metadata. Деструктивно и
// необратимо, поэтому роль admin и явный confirm обязательны (раздел 7.4
// архитектуры: удаление account — отдельная подтверждаемая операция).
// Необязательное тело {"reason":"..."} — причина удаления: попадает в
// payload операции, audit metadata и на успехе — в tombstone аккаунта.
func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != "true" {
		respondError(w, http.StatusBadRequest, "account deletion requires confirm=true query parameter")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	reason := ""
	if len(body) > 0 {
		var req deleteAccountRequest
		if err := json.Unmarshal(body, &req); err != nil {
			respondError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if reason, err = normalizeDeleteReason(req.Reason); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	acct, ok := s.requireManagedAccount(w, r, "deleted")
	if !ok {
		return
	}
	s.enqueueAccountOperation(w, r, acct, jobs.KindAccountDelete, auditActionAccountDeleteRequested,
		accountOperationOpts{reason: reason})
}

// purgeAccount — DELETE /api/v1/accounts/{id}/purge?confirm=true (admin):
// окончательно удаляет уже удалённый metadata tombstone. Target не трогается:
// soft-delete до этого уже доказал удаление identity. Audit сохраняет identity
// и actor, но сам account, bindings и собственный Vault credential исчезают.
func (s *Server) purgeAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.URL.Query().Get("confirm") != "true" {
		respondError(w, http.StatusBadRequest, "account purge requires confirm=true query parameter")
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if acct.Status != inventory.AccountDeleted {
		respondError(w, http.StatusConflict, "only a deleted account can be purged")
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	prepared, err := s.inventory.PreparePurgeDeletedAccount(ctx, tx, id)
	if err != nil {
		if errors.Is(err, inventory.ErrAccountStatusConflict) || errors.Is(err, inventory.ErrAccountLifecycleBusy) {
			respondError(w, http.StatusConflict, "account cannot be purged while its lifecycle is changing")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	// Строгая зачистка перед metadata выполняется под блокировкой account:
	// общий principal credential здесь no-op, собственный account credential
	// удаляется со всеми версиями. NotFound идемпотентен (обычный
	// account.delete уже чистит его best-effort).
	if err := s.credentials.DeleteAccountCredential(ctx, prepared.VaultPath); err != nil {
		slog.ErrorContext(ctx, "api: purge account credential", "account_id", id, "error", err)
		respondError(w, http.StatusBadGateway, "failed to purge account credential")
		return
	}
	purged, err := s.inventory.PurgeDeletedAccount(ctx, tx, id)
	if err != nil {
		if errors.Is(err, inventory.ErrAccountStatusConflict) || errors.Is(err, inventory.ErrAccountLifecycleBusy) {
			respondError(w, http.StatusConflict, "account cannot be purged while its lifecycle is changing")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	principalPurged := false
	var purgedPrincipal principals.Principal
	if purged.PrincipalID != nil {
		purgedPrincipal, principalPurged, err = s.principals.PurgeDeletedOrphan(ctx, tx, *purged.PrincipalID)
		if err != nil && !errors.Is(err, principals.ErrNotFound) {
			respondStoreError(ctx, w, err)
			return
		}
	}
	metadata, _ := json.Marshal(map[string]any{
		"engine_identity":   purged.EngineIdentity,
		"lifecycle_version": purged.LifecycleVersion,
		"principal_id":      purged.PrincipalID,
	})
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: auditActionAccountPurged,
		ConnectionID: &purged.ConnectionID, AccountID: &purged.ID,
		PrincipalID: purged.PrincipalID, Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if principalPurged {
		principalMetadata, _ := json.Marshal(map[string]any{
			"display_name": purgedPrincipal.DisplayName,
			"type":         purgedPrincipal.Type,
			"source":       "last_account_purge",
		})
		if err := s.audit.Write(ctx, tx, audit.Event{
			ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: auditActionPrincipalPurged,
			PrincipalID: &purgedPrincipal.ID, Result: audit.ResultSuccess, Metadata: principalMetadata,
		}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"account_id": purged.ID, "purged": true, "principal_purged": principalPurged,
	})
}

// restoreAccount — POST /api/v1/accounts/{id}/restore (admin): создаёт новую
// incarnation существующего managed login tombstone. Для linked account
// сохраняется principal link и применяется актуальная версия общего credential;
// локальный account получает новый собственный credential. Роли и bindings не
// восстанавливаются, metadata остаётся deleted до Apply+Verify+credential proof.
func (s *Server) restoreAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req restoreAccountRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if acct.Ownership != inventory.OwnershipManaged || !inventory.AccountHoldsCredential(acct) {
		respondError(w, http.StatusConflict, "only a managed login account can be restored")
		return
	}
	if acct.Status != inventory.AccountDeleted {
		respondError(w, http.StatusConflict, "only a deleted account can be restored")
		return
	}
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection status %q does not allow account restore", conn.Status))
		return
	}
	if conn.Engine == "postgres" {
		if _, err := requirePostgresProvisioningAuthority(conn, adapter.CapAccountRestore); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		respondError(w, http.StatusConflict, "account restore is unsupported for this connection engine")
		return
	}
	if !ad.Manifest().HasCapability(adapter.CapAccountRestore) {
		respondError(w, http.StatusConflict, "account restore is unsupported for this connection engine")
		return
	}
	if !slices.Contains(conn.Capabilities, string(adapter.CapAccountRestore)) {
		respondError(w, http.StatusConflict, "account restore capability is not enabled for this connection")
		return
	}
	bindings, err := s.inventory.ListBindingsByAccount(ctx, s.pool, acct.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(bindings) != 0 {
		respondError(w, http.StatusConflict, "deleted account has binding evidence and cannot be restored")
		return
	}

	var (
		password             []byte
		vaultVersion         int
		sharedCredentialPath string
	)
	switch req.Credential.Mode {
	case credentialModePrincipal:
		if acct.PrincipalID == nil {
			respondError(w, http.StatusConflict, "deleted account is not linked to a global user")
			return
		}
		sharedCredentialPath, err = vault.PrincipalEnvironmentCredentialPath(
			acct.PrincipalID.String(), environmentOf(conn))
		if err != nil || acct.CredentialMode == nil ||
			*acct.CredentialMode != inventory.CredentialModeExistingVaultRef ||
			acct.VaultPath != sharedCredentialPath {
			respondError(w, http.StatusConflict, "deleted account is not linked to the current principal credential")
			return
		}
		password, vaultVersion, err = s.credentials.GetPrincipalCredential(
			ctx, *acct.PrincipalID, environmentOf(conn))
		if err != nil {
			respondError(w, http.StatusBadGateway, "failed to read the current principal credential")
			return
		}
	case credentialModeGenerated:
		generated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
		if err != nil || generated == nil || len(generated.Secret) == 0 {
			slog.ErrorContext(ctx, "api: generate restore credential", "account_id", acct.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to generate account credential")
			return
		}
		password = generated.Secret
	default:
		password = []byte(req.Credential.Password)
	}
	defer clear(password)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, conn.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err = s.connections.Get(ctx, tx, conn.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var postgresPins postgresProvisioningPins
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, adapter.CapAccountRestore)
		if err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}

	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, inventory.AccountDeleted)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Reserve держит row lock до commit. Access enqueue берёт тот же lock и
	// reject'ит deleted, поэтому это повторное чтение закрывает TOCTOU между
	// предварительной eligibility-проверкой и записью credential.
	bindings, err = s.inventory.ListBindingsByAccount(ctx, tx, acct.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(bindings) != 0 {
		respondError(w, http.StatusConflict, "deleted account has binding evidence and cannot be restored")
		return
	}
	if req.Credential.Mode != credentialModePrincipal {
		vaultVersion, _, err = s.credentials.PutAccountCredential(ctx, acct.ID, acct.EngineIdentity, password)
		if err != nil {
			if errors.Is(err, credentials.ErrVaultNotConfigured) {
				respondError(w, http.StatusServiceUnavailable,
					"vault is not configured: cannot store account credential; set GRANTOR_VAULT_ADDR")
				return
			}
			slog.ErrorContext(ctx, "api: store restore credential", "account_id", acct.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to store account credential in vault")
			return
		}
	}
	payloadSharedCredentialPath := sharedCredentialPath
	operationKind := jobs.KindAccountRestore
	if conn.Engine == "postgres" {
		operationKind = jobs.KindPostgresAccountRestoreV2
		// The v2 worker derives the canonical path from the pinned account
		// incarnation; an operation payload must not carry a mutable path.
		payloadSharedCredentialPath = ""
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID:                     acct.ID,
		ExpectedStatus:                inventory.AccountDeleted,
		ExpectedLifecycleVersion:      reserved.LifecycleVersion,
		CredentialMode:                req.Credential.Mode,
		CredentialVaultVersion:        vaultVersion,
		SharedCredentialPath:          payloadSharedCredentialPath,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedTargetIdentity:        postgresPins.TargetIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal restore payload: %w", err))
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		PrincipalID:   acct.PrincipalID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		Action: auditActionAccountRestoreRequested, ConnectionID: &acct.ConnectionID,
		AccountID: &acct.ID, OperationID: &op.ID, Result: audit.ResultSuccess,
	}, map[string]any{
		"engine_identity":   acct.EngineIdentity,
		"credential_mode":   req.Credential.Mode,
		"lifecycle_version": reserved.LifecycleVersion,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit restore account: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id": acct.ID, "operation_id": op.ID,
	})
}

// rotateAccountRequest — необязательное тело POST /accounts/{id}/rotate.
type rotateAccountRequest struct {
	// Detach — явное намерение увести аккаунт с общего секрета принципала на
	// собственный путь accounts/<id>/credential. На аккаунте с личным
	// секретом флаг — no-op: он уже владеет собственным путём, и результат
	// запроса от флага не зависит. Так клиент, получивший 409
	// shared_credential_requires_choice, может безопасно повторить запрос с
	// detach даже если состояние успело измениться.
	Detach bool `json:"detach"`
	// Attach — обратное намерение: вернуть отвязанный аккаунт на общий пароль
	// его принципала (см. attachAccountToPrincipalCredential). Нового пароля
	// не создаёт: к цели применяется текущий общий секрет окружения.
	Attach bool `json:"attach"`
}

// validate отвергает взаимоисключающие намерения: detach уводит аккаунт с
// общего пароля, attach возвращает на него — вместе они бессмысленны, и
// молча предпочесть одно другому значит выполнить не то, что просили.
func (req rotateAccountRequest) validate() error {
	if req.Detach && req.Attach {
		return errors.New("detach and attach are mutually exclusive")
	}
	return nil
}

// accountSharesPrincipalCredential — топология credential аккаунта: он
// ссылается на общий секрет СВОЕГО принципала (ADR-0008: один пароль на пару
// principal+environment). Именно такой аккаунт нельзя ротировать «молча»:
// per-account ротация всегда пишет собственный путь, то есть уводит аккаунт
// с общего пароля.
//
// Указатель в раздел ЧУЖОГО принципала (AccountCredentialPointerForeign)
// осознанным выбором не является: он уже сломан, share по нему отказывает, и
// ротация — штатный способ его починить. Поэтому такой аккаунт ротируется
// без вопросов. Чистая функция для юнит-тестов.
func accountSharesPrincipalCredential(a inventory.Account) bool {
	return a.PrincipalID != nil &&
		a.CredentialMode != nil &&
		*a.CredentialMode == inventory.CredentialModeExistingVaultRef &&
		vault.IsPrincipalScopedPath(a.VaultPath) &&
		!inventory.AccountCredentialPointerForeign(a)
}

// accountRotatableOnSharedCredential — аккаунт, которого РЕАЛЬНО коснётся
// ротация общего секрета принципала: к топологии добавляются требования
// groupRotatablePrincipalAccounts (managed и живой active). Не-живые
// (provisioning/missing/deleted) в ротацию принципала не попадают, поэтому и
// в список затронутых их включать нельзя — счётчик врал бы оператору.
// Чистая функция для юнит-тестов.
func accountRotatableOnSharedCredential(a inventory.Account) bool {
	return accountSharesPrincipalCredential(a) &&
		a.Ownership == inventory.OwnershipManaged &&
		a.Status == inventory.AccountActive
}

// rotationRequiresConfirm сообщает, требует ли ротация общего секрета
// принципала явного подтверждения из-за своего масштаба: accounts — число
// аккаунтов, которым сменится пароль, threshold — порог
// GRANTOR_ROTATION_CONFIRM_THRESHOLD. Зеркалит approval.RequiresMassRevoke по
// форме (threshold <= 0 выключает gate, срабатывание строго БОЛЬШЕ порога),
// но не по механизму: подтверждение здесь — флаг того же запроса, а не
// approval-workflow со вторым админом. Ротацию часто делают в инциденте, и
// блокировать её ожиданием второго человека опаснее самой ротации.
// Чистая функция для юнит-тестов.
func rotationRequiresConfirm(threshold, accounts int) bool {
	return threshold > 0 && accounts > threshold
}

// sharedCredentialConnectionJSON — одно подключение, которого коснётся
// ротация общего секрета. Только несекретные метаданные control plane:
// путь секрета и тем более его значение сюда не попадают.
type sharedCredentialConnectionJSON struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	DisplayName  string    `json:"display_name"`
	AccountID    uuid.UUID `json:"account_id"`
}

// sharedCredentialContextJSON — контекст выбора: что именно стоит за общим
// секретом этого аккаунта и во что обойдётся ротация общего пароля.
type sharedCredentialContextJSON struct {
	PrincipalID          uuid.UUID                        `json:"principal_id"`
	PrincipalDisplayName string                           `json:"principal_display_name"`
	Environment          string                           `json:"environment"`
	AffectedAccounts     int                              `json:"affected_accounts"`
	AffectedConnections  []sharedCredentialConnectionJSON `json:"affected_connections"`
	ConfirmThreshold     int                              `json:"confirm_threshold"`
	RequiresConfirm      bool                             `json:"requires_confirm"`
}

// sharedCredentialConflictJSON — 409-ответ «нужен осознанный выбор».
type sharedCredentialConflictJSON struct {
	Error            string                      `json:"error"`
	Code             string                      `json:"code"`
	SharedCredential sharedCredentialContextJSON `json:"shared_credential"`
}

// rotateAccount — POST /api/v1/accounts/{id}/rotate (operator): ротация
// credential managed-аккаунта (новая версия в Vault + применение в
// целевой системе). Пустой vault_path не препятствие: у аккаунта,
// принятого через adopt mode=metadata, секрета в Vault ещё нет — первая
// ротация генерирует пароль, применяет его и заполняет
// vault_path/credential_mode (см. executeCredentialRotate).
//
// Аккаунт на общем секрете принципала — отдельный случай. Эта ротация
// физически не может обновить общий пароль: executor пишет
// accounts/<id>/credential, то есть уводит аккаунт с общего секрета. Раньше
// это происходило молча, и в результате общий секрет оставался со старым
// значением, соседние аккаунты принципала продолжали жить на нём, а
// /principals/{id}/share выдавал пароль, для отротированного аккаунта уже
// мёртвый. Теперь такой запрос без явного {"detach":true} отвечает 409 с
// машиночитаемым кодом и контекстом: оператор выбирает между ротацией общего
// пароля (POST /principals/{id}/rotate) и отвязкой этого аккаунта
// ({"detach":true}). Обратный путь — {"attach":true}: аккаунт возвращается на
// общий пароль принципала (см. attachAccountToPrincipalCredential).
func (s *Server) rotateAccount(w http.ResponseWriter, r *http.Request) {
	var req rotateAccountRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	acct, ok := s.requireManagedAccount(w, r, "rotated")
	if !ok {
		return
	}
	if req.Attach {
		s.attachAccountToPrincipalCredential(w, r, acct)
		return
	}
	detaching := accountSharesPrincipalCredential(acct)
	if detaching && !req.Detach {
		s.respondSharedCredentialChoice(w, r, acct)
		return
	}
	// Путь, по которому окажется credential после успешной ротации:
	// per-account ротация всегда пишет собственный раздел аккаунта
	// (executeCredentialRotate, rotateSourceGenerate). Возвращаем его сразу,
	// чтобы отвязка от общего секрета была видна и через API, а не только по
	// перечитанному аккаунту после завершения операции.
	ownPath, err := vault.AccountCredentialPath(acct.ID.String())
	if err != nil {
		respondStoreError(r.Context(), w, fmt.Errorf("api: account credential path: %w", err))
		return
	}
	s.enqueueAccountOperation(w, r, acct, jobs.KindCredentialRotate, auditActionRotateRequested,
		accountOperationOpts{extraResponse: map[string]any{"vault_path": ownPath, "detached": detaching}})
}

// attachAccountToPrincipalCredential — обратный путь отвязки: аккаунт
// возвращается на общий пароль своего принципала в окружении его подключения.
// Ставится обычная операция credential.rotate с SharedCredentialPath — тот же
// механизм, что у дочерних ротаций принципала: executor читает ТЕКУЩИЙ общий
// пароль и применяет его к целевой системе, нового не генерирует. Так аккаунт
// снова делит один пароль с остальными аккаунтами принципала (ADR-0008), и
// /principals/{id}/share опять выдаёт для него рабочее значение.
//
// credential_mode фиксируется сразу, vault_path — только на успехе операции
// (см. accountOperationOpts.credentialMode): до применения пароля к цели
// аккаунт продолжает жить на собственном рабочем секрете.
func (s *Server) attachAccountToPrincipalCredential(w http.ResponseWriter, r *http.Request, acct inventory.Account) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if acct.PrincipalID == nil {
		respondError(w, http.StatusConflict,
			"account is not linked to a principal: link it first to share the principal credential")
		return
	}
	if accountSharesPrincipalCredential(acct) {
		respondError(w, http.StatusConflict, "account already shares the credential of its principal")
		return
	}
	principal, err := s.principals.Get(ctx, s.pool, *acct.PrincipalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Секрет выключенного принципала не обновляется и не выдаётся, у
	// deleted его уже нет — те же правила, что у ротации и share принципала.
	if msg := principalStatusBlocks(principal.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}
	tx, beginErr := s.pool.Begin(ctx)
	if beginErr != nil {
		respondStoreError(ctx, w, beginErr)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	conn, ok := s.lockCredentialConnection(w, r, tx, acct.ConnectionID, adapter.CapCredentialRotate)
	if !ok {
		return
	}
	sharedPath, ok := s.ensurePrincipalEnvCredential(w, r, principal.ID, environmentOf(conn), map[string]string{})
	if !ok {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	s.enqueueAccountOperation(w, r, acct, jobs.KindCredentialRotate, auditActionRotateRequested,
		accountOperationOpts{
			sharedCredentialPath: sharedPath,
			credentialMode:       inventory.CredentialModeExistingVaultRef,
			extraResponse:        map[string]any{"vault_path": sharedPath, "attached": true},
		})
}

// respondSharedCredentialChoice пишет 409 с кодом
// shared_credential_requires_choice и контекстом выбора: принципал, его
// окружение и все подключения, которым сменит пароль ротация общего секрета.
// Контекст собирается ПОСЛЕ проверки scope: список чужих подключений и имя
// принципала operator'у вне его окружений не показываем.
func (s *Server) respondSharedCredentialChoice(w http.ResponseWriter, r *http.Request, acct inventory.Account) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	env := environmentOf(conn)
	principal, err := s.principals.Get(ctx, s.pool, *acct.PrincipalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	siblings, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, principal.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	// Общий секрет скоуплен парой (principal, environment), поэтому в список
	// попадают только аккаунты подключений ТОГО ЖЕ окружения: в других
	// окружениях у принципала независимый пароль.
	affected := make([]sharedCredentialConnectionJSON, 0, len(siblings))
	for i := range siblings {
		sib := siblings[i]
		if !accountRotatableOnSharedCredential(sib) {
			continue
		}
		sibConn := conn
		if sib.ConnectionID != conn.ID {
			if sibConn, err = s.connections.Get(ctx, s.pool, sib.ConnectionID); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
		}
		if environmentOf(sibConn) != env {
			continue
		}
		affected = append(affected, sharedCredentialConnectionJSON{
			ConnectionID: sibConn.ID,
			DisplayName:  sibConn.DisplayName,
			AccountID:    sib.ID,
		})
	}

	respondJSON(w, http.StatusConflict, sharedCredentialConflictJSON{
		Error: fmt.Sprintf(
			"account %q shares the credential of principal %q in environment %q with %d account(s): "+
				"rotating it here would silently move this account to its own secret and leave the shared one unchanged; "+
				"rotate the shared credential via POST /api/v1/principals/%s/rotate, "+
				"or repeat this request with {\"detach\":true} to give this account its own secret",
			acct.EngineIdentity, principal.DisplayName, env, len(affected), principal.ID),
		Code: errCodeSharedCredentialRequiresChoice,
		SharedCredential: sharedCredentialContextJSON{
			PrincipalID:          principal.ID,
			PrincipalDisplayName: principal.DisplayName,
			Environment:          env,
			AffectedAccounts:     len(affected),
			AffectedConnections:  affected,
			ConfirmThreshold:     s.rotationConfirmThreshold,
			RequiresConfirm:      rotationRequiresConfirm(s.rotationConfirmThreshold, len(affected)),
		},
	})
}

// getAccount — GET /api/v1/accounts/{id} (viewer): карточка учётной записи
// по её id. До этого аккаунт читался только списком по connection, из-за чего
// клиент, знающий лишь account_id (операция, принципал, 409 ротации), был
// вынужден лезть в метаданные напрямую. Scope применяется как к остальным
// connection-центричным чтениям: operator видит аккаунт только в connection
// своего окружения.
func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if sess, ok := auth.FromContext(ctx); ok {
		if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
	}
	respondJSON(w, http.StatusOK, toAccountJSON(acct))
}

// shareAccount — POST /api/v1/accounts/{id}/share (operator): одноразовая
// выдача credential через Yopass (раздел 18 архитектуры). Ссылка
// возвращается ровно один раз; в audit пишется только факт выдачи —
// без ссылки и без значений секрета.
func (s *Server) shareAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	// Per-subject лимит credential reveal/share (ADR-0007, R2) + метрика
	// попытки и детекция аномальной частоты (разделы 24/25). При превышении
	// лимита — 429.
	if !s.guardReveal(w, r, sess, metrics.OperationAccountShare) {
		return
	}
	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: operator выдаёт credential только в connections своих окружений.
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, _, err := lockAccountLifecycleSnapshot(ctx, tx, acct.ID, nil, false); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	acct, err = s.inventory.GetAccount(ctx, tx, acct.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Выдавать пароль можно только от учётки, которая на целевой системе
	// действительно есть. Гейт проверял лишь deleted, поэтому ссылка
	// выдавалась и на provisioning (учётки ещё нет: create не выполнялся или
	// упал), и на missing (её там уже нет). Получатель получал заведомо
	// мёртвый пароль, а audit писал успешную выдачу.
	if !inventory.IsLiveAccountStatus(acct.Status) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"account status %q does not allow sharing its credential: "+
				"the account does not exist on the target system", acct.Status))
		return
	}
	if !requireLoginAccount(w, acct, "shared") {
		return
	}
	if acct.VaultPath == "" {
		respondError(w, http.StatusConflict, "account has no stored credential to share")
		return
	}
	// Защита в глубину к сбросу указателя в LinkAccountPrincipal: путь в
	// разделе принципала обязан принадлежать ТЕКУЩЕМУ принципалу аккаунта.
	// Иначе выдача вернула бы актуальный общий пароль чужого принципала,
	// открывающий все его аккаунты в окружении, — и при этом уже не рабочий
	// для самого аккаунта. Эта проверка чинит и строки, испорченные до
	// исправления store: они существуют в базе и никакой миграцией не
	// «дочинятся» без обращения к Vault.
	if inventory.AccountCredentialPointerForeign(acct) {
		respondError(w, http.StatusConflict,
			"account credential reference points to a shared secret of another principal; "+
				"rotate the account credential to give it its own secret before sharing")
		return
	}

	link, err := s.credentials.ShareAccountCredential(ctx, acct.VaultPath, acct.EngineIdentity, shareTTLHours*time.Hour)
	if err != nil {
		switch {
		case errors.Is(err, credentials.ErrYopassNotConfigured):
			respondError(w, http.StatusServiceUnavailable,
				"yopass is not configured: one-time credential links are unavailable; set GRANTOR_YOPASS_API_URL")
		case errors.Is(err, credentials.ErrVaultNotConfigured):
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot read account credential; set GRANTOR_VAULT_ADDR")
		case errors.Is(err, vault.ErrNotFound):
			// Секрета в Vault нет: удалён мимо grantor либо не записан.
			// Общий текст про «одноразовую ссылку» уводил в сторону службы
			// доставки, тогда как ломается шаг раньше — само чтение пароля.
			respondError(w, http.StatusConflict,
				"account credential is missing in vault: it was deleted outside grantor or never stored; "+
					"rotate the credential to create a new one")
		default:
			// Ошибка не содержит секретов и ссылки (контракты vault/yopass).
			slog.ErrorContext(ctx, "api: share account credential", "account_id", acct.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to create one-time credential link")
		}
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionCredentialShared,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"channel":          "yopass",
		"expires_in_hours": shareTTLHours,
		"one_time":         true,
	}); err != nil {
		// Выдача без audit-события недопустима: ссылка не возвращается,
		// одноразовый секрет в Yopass истечёт по TTL.
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit account credential share: %w", err))
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{
		"link":             link,
		"expires_in_hours": shareTTLHours,
		"one_time":         true,
	})
}

// adoptAccountRequest — тело POST /api/v1/accounts/{id}/adopt. Password
// задаётся только в режимах set_password и verify_password, уходит
// исключительно в Vault и не логируется.
type adoptAccountRequest struct {
	Mode     string `json:"mode"`
	Password string `json:"password"`
	// AdoptBindings — вместе с аккаунтом принять под управление все его
	// unmanaged bindings (desired NULL -> present).
	AdoptBindings bool `json:"adopt_bindings"`
}

// canonicalMode приводит режим к каноническому имени: единственный синоним —
// legacy password -> set_password. Пустой и неизвестный режимы возвращаются
// как есть, их отклоняет validate.
func (req *adoptAccountRequest) canonicalMode() string {
	if req.Mode == adoptModeLegacyPassword {
		return adoptModeSetPassword
	}
	return req.Mode
}

// validate проверяет тело adopt-запроса. Тексты ошибок уходят клиенту с
// кодом 400 и значения password не содержат.
func (req *adoptAccountRequest) validate() error {
	switch req.canonicalMode() {
	case adoptModeMetadata:
		if req.Password != "" {
			return errors.New("password must not be set for metadata mode")
		}
	case adoptModeGenerate:
		if req.Password != "" {
			return errors.New("password must not be set for generate mode")
		}
	case adoptModeSetPassword:
		if req.Password == "" {
			return fmt.Errorf("password is required for %q mode", adoptModeSetPassword)
		}
	case adoptModeVerifyPassword:
		if req.Password == "" {
			return fmt.Errorf("password is required for %q mode", adoptModeVerifyPassword)
		}
	default:
		return fmt.Errorf("mode must be %q, %q, %q or %q",
			adoptModeMetadata, adoptModeGenerate, adoptModeSetPassword, adoptModeVerifyPassword)
	}
	return nil
}

// adoptAccount — POST /api/v1/accounts/{id}/adopt (operator): принятие
// существующего unmanaged-аккаунта под управление grantor. Движки хранят
// только хэш пароля, прочитать его нельзя, поэтому режимов четыре:
//
//   - metadata — только метаданные (как link/adopt binding): ownership
//     становится managed немедленно, целевая система не затрагивается,
//     операция не ставится — ответ 200. vault_path/credential_mode остаются
//     пустыми (grantor ещё не владеет секретом; их заполнит первая ротация);
//   - generate — grantor сам генерирует НОВЫЙ пароль: оператор ничего не
//     вводит, ставится обычная операция credential.rotate с флагами
//     adopt+generate — worker генерирует пароль adapter-генератором
//     (engine-safe контракт adapter.GenerateCredential), пишет его в Vault и
//     применяет к целевой системе, на успехе переводит ownership в managed
//     (credential_mode=generated). Ответ 202. Ни один пароль не проходит через
//     API-слой;
//   - set_password (прежнее имя password) — оператор задаёт НОВЫЙ пароль: он
//     записывается в Vault по accounts/<id>/credential ДО создания операции (в
//     payload/audit/логи не попадает), затем ставится обычная операция
//     credential.rotate с флагом adopt — она применяет именно эту версию к
//     целевой системе и на успехе переводит ownership в managed
//     (credential_mode=provided). Ответ 202. Прежний пароль учётной записи
//     после успеха не работает;
//   - verify_password — оператор подтверждает СУЩЕСТВУЮЩИЙ пароль: значение
//     кладётся во временный accounts/<id>/adopt-proof, ставится операция
//     account.adopt_verify, worker доказывает пароль на target
//     (adapter.CredentialProver) и только на успехе переносит его в
//     accounts/<id>/credential и переводит ownership в managed
//     (credential_mode=provided). Целевая система не мутируется ни на одном
//     пути: неверный пароль — отказ операции, учётка остаётся ровно такой,
//     какой была. Ответ 202.
//
// Разделение set_password и verify_password — суть контракта: одно и то же
// тело запроса раньше означало «перезаписать», хотя оператор, принимающий
// живую учётку с известным паролем, ожидает «подтвердить». Режим
// verify_password требует от движка умения доказать пароль
// (adapter.CredentialProver) и прямого режима исполнения — оба условия
// проверяются синхронно, ДО постановки операции и до записи чего-либо в Vault.
//
// generate, set_password и verify_password дают одинаковую гарантию: ownership
// переходит в managed ТОЛЬКО на успехе операции — состояния «managed без
// применённого credential» этот путь не создаёт.
//
// adopt_bindings принимает все unmanaged bindings аккаунта; наличие среди них
// dangerous permission требует роли admin (симметрично точечному adoptBinding).
// В режиме metadata это происходит сразу — там и сам аккаунт становится
// managed в той же транзакции. В остальных режимах bindings принимаются
// ТОЛЬКО на успехе операции: принятые заранее, при провале кред-операции они
// оставались бы управляемыми у неуправляемого аккаунта и убирали внешний
// грант из отчёта о дрифте, то есть «отмывали» его.
func (s *Server) adoptAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req adoptAccountRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: operator принимает аккаунты только в connections своих окружений.
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	conn, connErr := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if connErr != nil {
		respondStoreError(ctx, w, connErr)
		return
	}
	if conn.AuthMode == "none" {
		respondError(w, http.StatusConflict, "authentication_disabled: account adoption is unavailable")
		return
	}
	if acct.Status == inventory.AccountDeleted {
		respondError(w, http.StatusConflict, "account is deleted and cannot be adopted")
		return
	}
	// Missing — учётки на target больше нет: принимать под управление
	// нечего, а кредовые режимы упали бы на prove/rotate уже в worker.
	if acct.Status == inventory.AccountMissing {
		respondError(w, http.StatusConflict,
			"account is missing from the target system and cannot be adopted")
		return
	}
	if acct.Ownership == inventory.OwnershipManaged {
		respondError(w, http.StatusConflict, "account is already managed by grantor")
		return
	}
	if acct.PrincipalID != nil {
		respondError(w, http.StatusConflict, "linked account must be adopted through link-and-manage")
		return
	}
	// Учётка, под которой grantor управляет самим подключением, под
	// управление не принимается ни в каком режиме. В generate grantor сменил
	// бы ей пароль и не обновил admin credential подключения — управление
	// сломалось бы целиком; metadata-режим тоже запрещён, потому что дальше
	// он открывает delete/disable над той же учёткой. Отметку ставит
	// discovery (adapter.AttrConnectionAdmin).
	if adapter.AttrBool(decodeAttributes(acct.Attributes), adapter.AttrConnectionAdmin) {
		respondError(w, http.StatusConflict,
			"account is the admin credential of its connection and cannot be adopted: "+
				"managing it would break grantor's own access to the connection")
		return
	}
	// Роль без логина (kind=group), опубликованная тем же discovery как
	// назначаемое право, принимается под управление ТОЛЬКО как metadata:
	// grantor начинает отслеживать её bindings, целевая система не
	// затрагивается. Кредовые режимы для неё запрещены — у роли нет пароля,
	// поэтому rotate записал бы ей в Vault мусор, а share выдал бы заведомо
	// нерабочие креды. Запрет на delete/rotate/share живёт в своих ручках:
	// account.delete для такой роли означает на целевой системе DROP ROLE и
	// каскадный отзыв доступа у всех её членов.
	if !inventory.AccountHoldsCredential(acct) && req.canonicalMode() != adoptModeMetadata {
		respondError(w, http.StatusConflict,
			"only metadata adoption is available for a role without login: it has no password to confirm, set or generate")
		return
	}
	if req.AdoptBindings {
		dangerous, err := s.inventory.CountUnmanagedDangerousBindings(ctx, s.pool, acct.ID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if dangerous > 0 && !sess.Role.Allows(auth.RoleAdmin) {
			respondError(w, http.StatusForbidden,
				"adopting bindings with a dangerous permission requires admin role")
			return
		}
	}

	switch req.canonicalMode() {
	case adoptModeMetadata:
		s.adoptAccountMetadata(w, r, sess, acct, req.AdoptBindings)
	case adoptModeGenerate:
		s.adoptAccountGenerate(w, r, sess, acct, req.AdoptBindings)
	case adoptModeVerifyPassword:
		s.adoptAccountVerifyPassword(w, r, sess, acct, req)
	default:
		s.adoptAccountSetPassword(w, r, sess, acct, req)
	}
}

// adoptAccountMetadata выполняет режим metadata: одной транзакцией
// принимает bindings (по запросу), переводит ownership в managed и пишет
// audit-событие; отвечает 200 с обновлённым аккаунтом.
func (s *Server) adoptAccountMetadata(w http.ResponseWriter, r *http.Request, sess auth.Session, acct inventory.Account, adoptBindings bool) {
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, _, err := lockAccountLifecycleSnapshot(ctx, tx, acct.ID, nil, false); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	adopted := 0
	if adoptBindings {
		if adopted, err = s.inventory.AdoptAccountBindings(ctx, tx, acct.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	updated, err := s.inventory.SetAccountManaged(ctx, tx, acct.ID, "", "")
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionAccountAdopted,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"mode":             adoptModeMetadata,
		"engine_identity":  acct.EngineIdentity,
		"adopted_bindings": adopted,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit adopt account: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"account":          toAccountJSON(updated),
		"adopted_bindings": adopted,
	})
}

// adoptAccountSetPassword выполняет режим set_password: записывает НОВЫЙ
// пароль в Vault (до транзакции и до создания операции — в payload/audit он не
// попадает), затем ставит adopt-операцию credential.rotate, применяющую именно
// эту предзаписанную версию (generate=false). Ownership до успеха операции
// остаётся unmanaged; неудача применения оставляет версию в Vault
// неактивированной — retry сходится к ней.
func (s *Server) adoptAccountSetPassword(w http.ResponseWriter, r *http.Request, sess auth.Session, acct inventory.Account, req adoptAccountRequest) {
	password := []byte(req.Password)
	defer clear(password)
	s.enqueueAdoptRotate(w, r, sess, acct, req.AdoptBindings, false, adoptModeSetPassword, password)
}

// adoptAccountGenerate выполняет режим generate: без предзаписи пароля ставит
// adopt-операцию credential.rotate с флагом generate — пароль сгенерирует и
// применит worker (engine-safe adapter.GenerateCredential). Ни один секрет не
// проходит через API-слой. Ownership до успеха операции остаётся unmanaged.
func (s *Server) adoptAccountGenerate(w http.ResponseWriter, r *http.Request, sess auth.Session, acct inventory.Account, adoptBindings bool) {
	s.enqueueAdoptRotate(w, r, sess, acct, adoptBindings, true, adoptModeGenerate, nil)
}

// adoptAccountVerifyPassword выполняет режим verify_password: подтверждение
// СУЩЕСТВУЮЩЕГО пароля учётной записи без единой мутации на целевой системе.
//
// Порядок и границы ответственности:
//
//   - синхронные отказы (до Vault и до операции): движок не умеет доказывать
//     пароль (нет adapter.CredentialProver) — 409. Для connector worker
//     проверяет runtime marker и отправляет отдельный read-only proof job;
//   - проверяемый пароль пишется во ВРЕМЕННЫЙ accounts/<id>/adopt-proof, а не
//     по канонический путь: до подтверждения grantor не вправе выдавать его за
//     текущий пароль учётки. Версия закрепляется в payload (как у restore),
//     сам секрет в payload/audit/логи не попадает;
//   - операция account.adopt_verify: worker доказывает пароль, на успехе
//     переносит его в accounts/<id>/credential, переводит ownership в managed
//     (credential_mode=provided) и удаляет adopt-proof; на отказе целевая
//     система остаётся нетронутой, а adopt-proof удаляется вместе с
//     детерминированным отказом.
func (s *Server) adoptAccountVerifyPassword(w http.ResponseWriter, r *http.Request, sess auth.Session,
	acct inventory.Account, req adoptAccountRequest) {
	ctx := r.Context()
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := requireConnectionCapability(conn, adapter.CapCredentialProve); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	if !engineProvesCredential(conn.Engine) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"engine %q cannot confirm an existing password: adopt with %q is unavailable for connection %s; "+
				"use %q to set a new password or %q to take the account over without touching it",
			conn.Engine, adoptModeVerifyPassword, conn.ID, adoptModeSetPassword, adoptModeMetadata))
		return
	}
	password := []byte(req.Password)
	defer clear(password)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, ok := s.lockCredentialConnection(w, r, tx, acct.ConnectionID, adapter.CapCredentialProve); !ok {
		return
	}

	// Bindings принимаются на успехе операции (payload AdoptBindings), а не
	// здесь: доказательство пароля ещё впереди, и принятые заранее bindings
	// при провале остались бы управляемыми у неуправляемого аккаунта.
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, acct.Status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	proofVersion, err := s.credentials.PutAccountAdoptProof(ctx, acct.ID, acct.EngineIdentity, password)
	if err != nil {
		if errors.Is(err, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot stage account credential; set GRANTOR_VAULT_ADDR")
			return
		}
		slog.ErrorContext(ctx, "api: stage adopt proof credential", "account_id", acct.ID, "error", err)
		respondError(w, http.StatusBadGateway, "failed to stage account credential in vault")
		return
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, Adopt: true,
		ExpectedStatus: acct.Status, ExpectedLifecycleVersion: reserved.LifecycleVersion,
		CredentialVaultVersion: proofVersion,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          jobs.KindAccountAdoptVerify,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionAccountAdoptRequested,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"mode":                  adoptModeVerifyPassword,
		"engine_identity":       acct.EngineIdentity,
		"adopt_bindings":        req.AdoptBindings,
		"bindings_adopted_with": "operation",
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit adopt account: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id":     acct.ID,
		"operation_id":   op.ID,
		"adopt_bindings": req.AdoptBindings,
	})
}

// enqueueAdoptRotate — общий хвост режимов generate и set_password: одной
// транзакцией принимает bindings (по запросу), ставит операцию
// credential.rotate с флагом adopt (и generate для режима generate) и пишет
// audit-событие adopt_requested; отвечает 202. Payload режима set_password
// (generate=false) идентичен прежнему побайтово: AdoptGenerate omitempty
// опускает поле.
func (s *Server) enqueueAdoptRotate(w http.ResponseWriter, r *http.Request, sess auth.Session, acct inventory.Account,
	adoptBindings, generate bool, mode string, providedPassword []byte) {
	ctx := r.Context()
	// Оба режима применяют credential к целевой системе операцией
	// credential.rotate: движок без этой capability отказал бы в adapter.
	if !s.requireEngineCapability(w, r, acct, jobs.KindCredentialRotate) {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, ok := s.lockCredentialConnection(w, r, tx, acct.ConnectionID, adapter.CapCredentialRotate); !ok {
		return
	}

	// Bindings принимаются не здесь, а на успехе операции (payload
	// AdoptBindings): принятые заранее, при провале кред-операции они
	// оставались бы управляемыми у неуправляемого аккаунта и убирали внешний
	// грант из отчёта о дрифте — то есть «отмывали» его.
	if acct.Status == inventory.AccountDeleted {
		respondError(w, http.StatusConflict, "deleted account cannot be adopted")
		return
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, acct.Status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(providedPassword) > 0 {
		// Username — engine identity аккаунта: та же семантика, что у
		// ротации. Запись выполняется под lifecycle row lock до enqueue.
		if _, _, err := s.credentials.PutAccountCredential(ctx, acct.ID, acct.EngineIdentity, providedPassword); err != nil {
			if errors.Is(err, credentials.ErrVaultNotConfigured) {
				respondError(w, http.StatusServiceUnavailable,
					"vault is not configured: cannot store account credential; set GRANTOR_VAULT_ADDR")
				return
			}
			slog.ErrorContext(ctx, "api: store adopted account credential", "account_id", acct.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to store account credential in vault")
			return
		}
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, Adopt: true, AdoptGenerate: generate, AdoptBindings: adoptBindings,
		ExpectedStatus: acct.Status, ExpectedLifecycleVersion: reserved.LifecycleVersion,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          jobs.KindCredentialRotate,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionAccountAdoptRequested,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"mode":                  mode,
		"engine_identity":       acct.EngineIdentity,
		"adopt_bindings":        adoptBindings,
		"bindings_adopted_with": "operation",
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit adopt account: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id":     acct.ID,
		"operation_id":   op.ID,
		"adopt_bindings": adoptBindings,
	})
}
