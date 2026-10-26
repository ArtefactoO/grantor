package jobs

// Операция account.adopt_verify — принятие существующего аккаунта под
// управление ПОДТВЕРЖДЕНИЕМ его текущего пароля (adopt mode=verify_password).
//
// Отличие от adopt mode=set_password (операция credential.rotate с флагом
// adopt) принципиальное и составляет весь смысл этого файла: set_password
// ЗАМЕНЯЕТ пароль учётной записи на переданный, а verify_password ничего на
// целевой системе не меняет — он лишь доказывает через
// adapter.CredentialProver, что target принимает именно этот пароль именно для
// этой identity. Опечатка оператора в первом режиме тихо ломает работающее
// приложение, во втором — приводит к отказу операции, а на target не остаётся
// следов.
//
// Порядок шагов выбран так, чтобы grantor никогда не объявлял своим
// неподтверждённый секрет:
//
//  1. API-слой кладёт проверяемый пароль во ВРЕМЕННЫЙ путь
//     accounts/<id>/adopt-proof (в payload операции секретов нет по инварианту,
//     Vault — единственный канал доставки секрета worker'у) и закрепляет
//     версию в payload;
//  2. worker читает ровно эту версию и вызывает ProveCredential;
//  3. только на успехе пароль пишется новой версией по каноническому
//     accounts/<id>/credential, ownership переходит в managed
//     (credential_mode=provided), а adopt-proof удаляется;
//  4. на детерминированном отказе (пароль отвергнут, чужая identity, движок не
//     умеет доказывать) adopt-proof тоже удаляется: неподтверждённое значение
//     не остаётся в Vault, а по каноническому пути «неактивированной» версии
//     не появляется вовсе.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// adoptVerifyAuditMode — значение поля mode в audit-метаданных успеха: то же
// имя режима, что принимает API (api.adoptModeVerifyPassword), чтобы события
// enqueue (account.adopt_requested) и исхода (account.adopted) сходились по
// режиму. Дублирование константы вместо импорта: пакет jobs не зависит от api.
const adoptVerifyAuditMode = "verify_password"

// terminalAdoptVerifyCodes — коды отказа account.adopt_verify, исход которых не
// изменится от повтора: движок не умеет доказывать пароль, target отверг
// пароль или ответил чужой identity, состояние аккаунта уехало. Коды
// *_unavailable/*_failed сюда не входят — за ними стоит временная
// недоступность Vault, target или metadata database (terminal.go).
//
// Как и у account.restore, отдельный список нужен потому, что наружу уходит
// sanitized текст без исходной цепочки ошибок: errors.Is по ней уже не
// работает, а классификация обязана остаться точной.
var terminalAdoptVerifyCodes = map[string]bool{
	"credential_access_denied":     true,
	"lifecycle_conflict":           true,
	"ineligible_account":           true,
	"credential_identity_mismatch": true,
	"credential_proof_unsupported": true,
	"password_rejected":            true,
}

// adoptProofRemovable сообщает, что после отказа с этим кодом временный
// adopt-proof больше не нужен: повтора операции не будет. Ошибки чтения Vault
// и недоступность target остаются повторяемыми, и секрет обязан дожить до
// retry.
func adoptProofRemovable(code string) bool { return terminalAdoptVerifyCodes[code] }

// executeAccountAdoptVerify исполняет account.adopt_verify (см. заголовок
// файла). Целевая система не мутируется ни на одном пути исполнения: adapter
// вызывается ровно одним методом ProveCredential, который только
// аутентифицируется.
func (e *MainExecutor) executeAccountAdoptVerify(ctx context.Context, op operations.Operation) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccountPayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, payload.AccountID)
	if err != nil {
		return wrap(err)
	}
	fail := func(code string, returned error) error {
		return e.failAccountAdoptVerify(ctx, op, acct, code, returned)
	}
	if op.AccountID != nil && *op.AccountID != acct.ID {
		return fail("lifecycle_conflict", wrap(errors.New("operation account does not match payload")))
	}
	// Успех уже мог закоммититься (metadata + audit) при незакоммиченной
	// внешней транзакции операции: повтор такого job видит managed-аккаунт на
	// том же поколении lifecycle. Это durable-доказательство пройденного
	// proof — target повторно не трогаем.
	if acct.Ownership == inventory.OwnershipManaged &&
		acct.LifecycleVersion == payload.ExpectedLifecycleVersion {
		e.setResultArtifact(op.ID, adoptVerifyResult(payload.CredentialVaultVersion))
		return nil
	}
	// Пустой ExpectedStatus (legacy payload) означает «статус не пинится»:
	// guarded UPDATE ниже всё равно сравнивает статус, поэтому подставляем
	// текущий — как это делает executeCredentialRotate.
	expectedStatus := payload.ExpectedStatus
	if expectedStatus == "" {
		expectedStatus = acct.Status
	}
	if err := inventory.CheckAccountLifecycle(acct, expectedStatus, payload.ExpectedLifecycleVersion); err != nil {
		return fail("lifecycle_conflict", wrap(err))
	}
	if acct.Status == inventory.AccountDeleted || acct.Kind != "login" ||
		acct.Ownership != inventory.OwnershipUnmanaged {
		return fail("ineligible_account",
			wrap(fmt.Errorf("account %s is not an adoptable unmanaged login", acct.ID)))
	}
	if e.mut.Credentials == nil {
		return fail("credentials_unavailable", wrap(errors.New("credentials service is not configured")))
	}

	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return fail("target_unavailable", wrap(errors.New("adopt verification target is unavailable")))
	}
	if viaConnector {
		if err := e.requireActiveConnectorCapability(connector.CapCredentialProofV1); err != nil {
			return fail("connector_unavailable", wrap(errors.New("current-password verification requires an online connector with credential proof v1; update the connector and retry")))
		}
	}
	proofAdapter, err := managedLinkProofAdapter(conn.Engine, ad, viaConnector)
	if err != nil || !adapter.SupportsCredentialProof(proofAdapter) {
		return fail("credential_proof_unsupported",
			wrap(fmt.Errorf("engine %q cannot prove an existing password: %w",
				conn.Engine, adapter.ErrCredentialProofUnsupported)))
	}

	username, password, err := e.mut.Credentials.GetAccountAdoptProofVersion(ctx, acct.ID, payload.CredentialVaultVersion)
	if err != nil {
		return fail("credential_unavailable", wrap(errors.New("adopt proof credential is unavailable")))
	}
	defer clear(password)
	if username != acct.EngineIdentity {
		return fail("credential_identity_mismatch",
			wrap(fmt.Errorf("adopt proof identity does not match account: %w", adapter.ErrExternalIdentityConflict)))
	}

	credential := adapter.Credential{Kind: "password", Username: username, Secret: password}
	if viaConnector {
		err = e.connectorProveCredential(ctx, op, conn, cfg, acct, credential, payload.CredentialVaultVersion)
	} else {
		err = proofAdapter.(adapter.CredentialProver).ProveCredential(ctx, cfg, adapterAccount(acct), credential)
	}
	if err != nil {
		// Текст adapter может нести endpoint и детали схемы аутентификации,
		// поэтому наружу уходит только стабильный код.
		code := "target_unavailable"
		switch {
		case errors.Is(err, adapter.ErrCredentialProofAccessDenied):
			code = "credential_access_denied"
		case errors.Is(err, adapter.ErrExternalIdentityConflict):
			code = "password_rejected"
		case errors.Is(err, adapter.ErrCredentialProofUnsupported):
			code = "credential_proof_unsupported"
		}
		message := "adopt verification failed: " + code
		if code == "credential_access_denied" {
			message += "; check LOGIN and pg_hba.conf admission to an existing database"
		}
		return fail(code, wrap(errors.New(message)))
	}

	// Пароль подтверждён — теперь он честно «текущий пароль учётной записи», и
	// только теперь попадает по каноническому пути.
	version, path, err := e.mut.Credentials.PutAccountCredential(ctx, acct.ID, username, password)
	if err != nil {
		return fail("credential_store_failed", wrap(errors.New("proved credential could not be stored")))
	}
	metadata, err := json.Marshal(map[string]any{
		"account":           acct.EngineIdentity,
		"mode":              adoptVerifyAuditMode,
		"credential_mode":   inventory.CredentialModeProvided,
		"credential_proved": true,
		"vault_version":     version,
	})
	if err != nil {
		return fail("audit_metadata_invalid", wrap(errors.New("adopt audit metadata is invalid")))
	}
	e.setResultArtifact(op.ID, adoptVerifyResult(version))
	if err := e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, auditActionAccountAdopted, metadata, wrap,
		func(tx pgx.Tx) error {
			if _, err := e.deps.Inventory.SetAccountManagedGuarded(ctx, tx, acct.ID,
				expectedStatus, payload.ExpectedLifecycleVersion, path, inventory.CredentialModeProvided); err != nil {
				return err
			}
			if payload.AdoptBindings {
				_, err := e.deps.Inventory.AdoptAccountBindings(ctx, tx, acct.ID)
				return err
			}
			return nil
		}); err != nil {
		return err
	}
	e.dropAdoptProof(ctx, op, acct)
	return nil
}

// adoptVerifyResult собирает несекретный result-артефакт операции: факт
// принятия, факт доказательства пароля и номер версии Vault.
func adoptVerifyResult(version int) []byte {
	// Маршалинг фиксированной map со скалярами не может упасть; ошибку
	// сознательно не поднимаем, чтобы артефакт не мешал исходу операции.
	raw, err := json.Marshal(map[string]any{
		"adopted": true, "credential_proved": true, "vault_version": version,
	})
	if err != nil {
		return nil
	}
	return raw
}

// dropAdoptProof удаляет временный adopt-proof best-effort: исход операции от
// удаления не зависит, но оставлять проверяемый пароль в Vault не нужно.
func (e *MainExecutor) dropAdoptProof(ctx context.Context, op operations.Operation, acct inventory.Account) {
	if e.mut.Credentials == nil {
		return
	}
	if err := e.mut.Credentials.DeleteAccountAdoptProof(ctx, acct.ID); err != nil {
		slog.WarnContext(ctx, "jobs: adopt proof cleanup failed",
			"operation_id", op.ID, "account_id", acct.ID, "error", err)
	}
}

// failAccountAdoptVerify пишет в audit только стабильный sanitized code
// (исходные ошибки Vault/adapter могут содержать endpoint и path), убирает
// ставший ненужным adopt-proof и классифицирует отказ для политики повторов.
func (e *MainExecutor) failAccountAdoptVerify(ctx context.Context, op operations.Operation,
	acct inventory.Account, code string, returned error) error {
	safe := errors.New("account adopt verification failed: " + code)
	if adoptProofRemovable(code) {
		e.dropAdoptProof(ctx, op, acct)
	}
	if err := e.recordMutationFailure(ctx, op, acct.ConnectionID, &acct.ID, nil,
		auditActionAccountAdoptFailed, safe); err != nil {
		// Отказ записи audit — временная проблема metadata database, а не
		// причина отказа: job остаётся повторяемым.
		return errors.Join(returned, err)
	}
	if terminalAdoptVerifyCodes[code] {
		return terminal(returned)
	}
	return returned
}
