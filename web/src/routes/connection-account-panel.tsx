// Панель выбранного аккаунта с действиями по ролям. Логика мутаций и
// состояние диалогов вынесены в useAccountActions; здесь — рендер панели и
// сопутствующих drawer'ов/диалогов.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import {
  KeyRound,
  Link2,
  Power,
  PowerOff,
  RotateCw,
  RotateCcw,
  ShieldCheck,
  Trash2,
  Users,
  UserPlus,
} from '@project/ui/icons'
import { apiList } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type { Account, Binding, Connection, Permission, Principal, Resource } from '../lib/types'
import {
  inventoryStatusTone,
  ownershipTone,
  shortId,
} from '../lib/status'
import { formatDateTime } from '../lib/time'
import {
  accountActions,
  isConnectionAdminAccount,
  isSharedRoleKind,
  restoreBindingEligibility,
  sharedRolePermission,
} from '../lib/account-actions'
import { isActiveAccessBinding } from '../lib/active-access'
import { inventoryStatusLabel, ownershipLabel } from '../lib/ui-copy'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { Button, ErrorBanner, Spinner } from '@project/ui'
import { KindBadge, PrincipalTypeChip, StatusChip, TagBadge } from '../components/ui/badge'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { ShareLinkDialog } from '../components/ui/share-link-dialog'
import type { OperationAnchor } from '../components/operation-progress-notice'
import { AccountPermissionsSection } from '../components/account-permissions-section'
import { PostgresObjectAccess } from '../components/postgres-object-access'
import { accountDirectObjectCount, bindingManagementEligible, directObjectSummary, isPostgresObjectPrivilege, objectRecord, withoutObjectPrivileges } from '../lib/postgres-object-acl'
import {
  AccessImpactPreview,
  AccessLens,
  buildAccessLensModel,
} from '../components/access-lens'
import {
  AttributesSection,
  KeyValueList,
  SidePanel,
} from './connection-panels'
import { useAccountActions } from './connection-account-actions'
import type { ConfirmKind } from './connection-account-actions'
import {
  AdoptAccountDialog,
  AssignSharedRoleDrawer,
  DeleteAccountDialog,
  ManageRolesDrawer,
  LinkPrincipalDialog,
} from './connection-account-dialogs'
import { RestoreAccountDialog } from './connection-account-restore'
import { environmentLabel } from './principal-detail-shared'
import { UnlinkAccountButton } from '../components/ui/unlink-account-button'
import { RotateChoiceDialog } from './connection-account-rotate'
import { directlyOwnedPostgresDatabases } from '../lib/postgres-database-ownership'
import { AccountDatabaseOwnership } from '../components/account-database-ownership'
import { AccountHBASection } from './connection-hba-section'
import type { ConnectionHBAQuery } from './connection-hba-section'
import {
  AccountProvisioningNotice,
  accountProvisioningPresentation,
  useAccountProvisioning,
} from './connection-account-provisioning'

// Тексты маленьких confirm-диалогов disable/enable/rotate.
const CONFIRM_COPY: Record<
  ConfirmKind,
  { title: string; confirmLabel: string; describe: (identity: string) => ReactNode }
> = {
  disable: {
    title: 'Отключить аккаунт',
    confirmLabel: 'Отключить',
    describe: (identity) => (
      <>
        Аккаунт <span className="font-mono text-text">{identity}</span> будет отключён
        в целевой системе: вход по его credential перестанет работать до включения.
      </>
    ),
  },
  enable: {
    title: 'Включить аккаунт',
    confirmLabel: 'Включить',
    describe: (identity) => (
      <>
        Аккаунт <span className="font-mono text-text">{identity}</span> будет снова
        включён в целевой системе.
      </>
    ),
  },
  rotate: {
    title: 'Ротация пароля',
    confirmLabel: 'Ротировать',
    describe: (identity) => (
      <>
        Пароль аккаунта <span className="font-mono text-text">{identity}</span> будет
        заменён: новая версия сохранится в Vault и применится в целевой системе.
        Старый пароль перестанет действовать.
      </>
    ),
  },
  attach: {
    title: 'Вернуть на общий пароль',
    confirmLabel: 'Вернуть',
    describe: (identity) => (
      <>
        Аккаунт <span className="font-mono text-text">{identity}</span> снова начнёт
        использовать общий пароль своего пользователя в этом окружении: к целевой
        системе применится текущее общее значение, собственный пароль аккаунта
        перестанет действовать. Новый пароль при этом не создаётся, остальные
        аккаунты пользователя не затрагиваются.
      </>
    ),
  },
}

interface AccountDetailPanelProps {
  hbaQuery?: ConnectionHBAQuery
  directAccessRequest?: number
  account: Account
  connection: Connection
  permissions: Permission[]
  permissionsById: Map<string, Permission>
  resourcesById: Map<string, Resource>
  onClose: () => void
  onNotice: (text: string) => void
  onOperationStarted: (operationId: string, label: string, anchor?: OperationAnchor) => void
}

/** Обёртка со стабильной идентичностью для AnimatePresence: смена выбранного
 * аккаунта не проигрывает пару exit/enter двух панелей рядом («фантом»
 * затухающей старой), анимируются только открытие и закрытие панели целиком.
 * key на контенте при этом полностью сбрасывает внутреннее состояние
 * (диалоги, поля) под новый аккаунт. */
export function AccountDetailPanel(props: AccountDetailPanelProps) {
  return <AccountPanelContent key={props.account.id} {...props} />
}

function AccountPanelContent({
  hbaQuery,
  directAccessRequest = 0,
  account,
  connection,
  permissions,
  permissionsById,
  resourcesById,
  onClose,
  onNotice,
  onOperationStarted,
}: AccountDetailPanelProps) {
  const auth = useAuth()
  const canOperate = roleAtLeast(auth.role, 'operator')
  const provisioning = useAccountProvisioning(account)
  const provisioningStatus = accountProvisioningPresentation(provisioning)
  // Единый предикат доступных действий (kind/ownership/status/credential/роль).
  const actions = accountActions(account, auth.role, connection)
  const sharedRole = isSharedRoleKind(account.kind)
  const rolePermission = useMemo(
    () => sharedRolePermission(account, permissions),
    [account, permissions],
  )
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [assignRoleOpen, setAssignRoleOpen] = useState(false)
  const [linkIntent, setLinkIntent] = useState<'record' | 'managed'>('record')

  const bindingsQuery = useQuery({
    queryKey: qk.accountBindings(account.id, connection.engine === 'postgres' ? 'roles' : undefined),
    queryFn: ({ signal }) =>
      apiList<Binding>(`/api/v1/accounts/${account.id}/bindings${connection.engine === 'postgres' ? '?category=roles' : ''}`, 'bindings', signal),
  })
  const hbaRoles = useMemo(() => new Set(
    (bindingsQuery.data ?? []).flatMap((binding) => {
      if (binding.observed_state !== 'present') return []
      const externalId = permissionsById.get(binding.observed_permission_definition_id ?? binding.permission_definition_id)?.external_id
      return externalId?.startsWith('role:') ? [externalId.slice(5)] : []
    }),
  ), [bindingsQuery.data, permissionsById])

  // Principals нужны блоку «Пользователь»: имя по principal_id и список
  // для диалога привязки; ключ общий с экраном «Пользователи».
  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
  })

  const linkedPrincipal =
    account.principal_id !== null
      ? ((principalsQuery.data ?? []).find((p) => p.id === account.principal_id) ??
        null)
      : null
  const canManageLinked =
    actions.manageLinked && linkedPrincipal?.status === 'active'
  const ownedDatabases = useMemo(
    () => directlyOwnedPostgresDatabases(account, connection, [...resourcesById.values()]),
    [account, connection, resourcesById],
  )

  const alive = account.status !== 'deleted'
  const canMutateAccount = canOperate && alive && account.status !== 'provisioning'
  const canAssignRole = canMutateAccount && rolePermission !== null

  // Unmanaged bindings (desired_state == null) — для чекбокса «Взять под
  // управление текущие права» и списка их чипов в диалоге adopt.
  const unmanagedBindings = (bindingsQuery.data ?? []).filter(
    (binding) => binding.desired_state === null && isActiveAccessBinding(binding) && bindingManagementEligible(binding),
  )
  const restoreEligibility = restoreBindingEligibility(actions.restore, bindingsQuery)
  const canRestore = restoreEligibility === 'eligible'

  const {
    rolesOpen,
    setRolesOpen,
    revokeBinding,
    setRevokeBinding,
    revokeOpen,
    setRevokeOpen,
    share,
    shareOpen,
    setShareOpen,
    confirmKind,
    confirmOpen,
    setConfirmOpen,
    deleteOpen,
    setDeleteOpen,
    purgeOpen,
    setPurgeOpen,
    linkOpen,
    setLinkOpen,
    unlinkOpen,
    setUnlinkOpen,
    adoptOpen,
    setAdoptOpen,
    rotateChoice,
    rotateChoiceOpen,
    setRotateChoiceOpen,
    actionError,
    setActionError,
    invalidate,
    invalidateLink,
    unlinkMutation,
    shareMutation,
    revokeMutation,
    lifecycleMutation,
    purgeMutation,
    sharedRotateMutation,
    openConfirm,
    startRotate,
    submitRotateChoice,
  } = useAccountActions(account, connection.id, onNotice, onOperationStarted, onClose)

  const revokePermissionName =
    revokeBinding !== null
      ? (permissionsById.get(revokeBinding.permission_definition_id)?.name ??
        shortId(revokeBinding.permission_definition_id))
      : ''
  const accessModel = useMemo(
    () => ({ ...buildAccessLensModel(bindingsQuery.data ?? [], permissionsById, resourcesById), ...(account.access_summary === undefined ? {} : { directObjects: account.access_summary.direct_objects }) }),
    [account.access_summary, bindingsQuery.data, permissionsById, resourcesById],
  )
  const revokeAccessModel = useMemo(
    () =>
      buildAccessLensModel(
        revokeBinding === null ? [] : [revokeBinding],
        permissionsById,
        resourcesById,
      ),
    [permissionsById, resourcesById, revokeBinding],
  )

  // Drawers и диалоги позиционируются fixed, поэтому рендерятся сиблингами
  // SidePanel: внутри анимируемой панели transform ломал бы их позиционирование.
  return (
    <>
      <SidePanel
        title={account.engine_identity}
        copyTitle
        onClose={onClose}
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <TagBadge>
              <KindBadge kind={account.kind} principalType={linkedPrincipal?.type} />
            </TagBadge>
            {!sharedRole && (
              <StatusChip tone={ownershipTone(account.ownership)}>
                {ownershipLabel(account.ownership)}
              </StatusChip>
            )}
            <StatusChip tone={account.status === 'provisioning' ? provisioningStatus.tone : inventoryStatusTone(account.status)}>
              {account.status === 'provisioning' ? provisioningStatus.label : inventoryStatusLabel(account.status)}
            </StatusChip>
            {isConnectionAdminAccount(account) && (
              <StatusChip tone="accent">Учётка подключения</StatusChip>
            )}
          </div>

          {account.status === 'provisioning' && (
            <AccountProvisioningNotice
              account={account}
              provisioning={provisioning}
              isAdmin={roleAtLeast(auth.role, 'admin')}
              canOperate={canOperate}
              onOperationStarted={onOperationStarted}
            />
          )}

          {/* Без пояснения скрытые adopt/link выглядят багом: у соседних
              unmanaged-строк кнопки есть, а здесь их нет. */}
          {isConnectionAdminAccount(account) && (
            <p className="rounded-md border border-line bg-panel2/40 px-3 py-2 text-xs text-muted">
              Под этой учётной записью grantor управляет подключением. Принять её
              под управление нельзя: смена пароля отняла бы у grantor доступ.
            </p>
          )}

          {/* Набор кнопок — из единого предиката accountActions: показываем
              только реально применимые к этому аккаунту (kind/ownership/
              status/наличие credential/роль), чтобы у групповых ролей и
              unmanaged не висели бессмысленные действия. */}
          {((actions.anyPrimary || canAssignRole) &&
            (!actions.restore || canRestore)) && (
            <div className="flex flex-wrap gap-1.5">
              {canAssignRole && (
                <Button size="sm" onClick={() => setAssignRoleOpen(true)}>
                  <UserPlus className="size-3.5" />
                  Назначить пользователям
                </Button>
              )}
              {actions.grant && (
                <Button size="sm" onClick={() => setRolesOpen(true)}>
                  <KeyRound className="size-3.5" />
                  Управление ролями
                </Button>
              )}
              {actions.share && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={shareMutation.isPending}
                  onClick={() => shareMutation.mutate()}
                >
                  {shareMutation.isPending ? (
                    <Spinner className="size-3.5" />
                  ) : (
                    <Link2 className="size-3.5" />
                  )}
                  Получить учётные данные
                </Button>
              )}
              {/* Ротация доступна и без сохранённого credential: у аккаунта,
                  принятого без пароля, первая ротация создаёт секрет. */}
              {actions.rotate && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={lifecycleMutation.isPending}
                  onClick={startRotate}
                >
                  <RotateCw className="size-3.5" />
                  Ротировать пароль
                </Button>
              )}
              {/* Обратный путь к отвязке: аккаунт с личным паролем можно
                  вернуть на общий пароль своего пользователя. */}
              {actions.attachShared && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openConfirm('attach')}
                >
                  <Users className="size-3.5" />
                  Вернуть на общий пароль
                </Button>
              )}
              {actions.adopt && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setAdoptOpen(true)}
                >
                  <ShieldCheck className="size-3.5" />
                  Взять под управление
                </Button>
              )}
              {canManageLinked && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setLinkIntent('managed')
                    setLinkOpen(true)
                  }}
                >
                  <ShieldCheck className="size-3.5" />
                  Перевести под управление
                </Button>
              )}
              {canRestore && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setRestoreOpen(true)}
                >
                  <RotateCcw className="size-3.5" />
                  Восстановить
                </Button>
              )}
              {actions.purge && (
                <Button variant="danger" size="sm" onClick={() => setPurgeOpen(true)}>
                  <Trash2 className="size-3.5" />
                  Удалить навсегда
                </Button>
              )}
              {actions.enable && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openConfirm('enable')}
                >
                  <Power className="size-3.5" />
                  Включить
                </Button>
              )}
              {actions.disable && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openConfirm('disable')}
                >
                  <PowerOff className="size-3.5" />
                  Отключить
                </Button>
              )}
              {actions.delete && (
                <Button variant="danger" size="sm" onClick={() => setDeleteOpen(true)}>
                  <Trash2 className="size-3.5" />
                  Удалить
                </Button>
              )}
            </div>
          )}

          {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}
          {restoreEligibility === 'loading' && (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Spinner className="size-3.5" />
              Проверяем, что у удалённого аккаунта не осталось прав…
            </div>
          )}
          {restoreEligibility === 'error' && (
            <ErrorBanner>
              Не удалось проверить оставшиеся права. Восстановление заблокировано
              до успешной проверки.
              <Button
                variant="outline"
                size="sm"
                className="ml-2"
                onClick={() => void bindingsQuery.refetch()}
              >
                Повторить
              </Button>
            </ErrorBanner>
          )}
          {restoreEligibility === 'blocked' && (
            <ErrorBanner>
              Восстановление недоступно: у удалённого аккаунта ещё есть права.
              Дождитесь завершения удаления или синхронизации и повторите.
            </ErrorBanner>
          )}

          <AccessLens
            account={account}
            connection={connection}
            principal={linkedPrincipal}
            bindings={bindingsQuery.data}
            permissionsById={permissionsById}
            resourcesById={resourcesById}
            pending={bindingsQuery.isPending || principalsQuery.isPending}
            error={bindingsQuery.isError || principalsQuery.isError}
          />

          <AccountDatabaseOwnership databases={ownedDatabases} detail />

          {!sharedRole && (
            <div>
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-faint">
                Пользователь
              </div>
              {account.principal_id === null ? (
                actions.link ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setLinkIntent('record')
                      setLinkOpen(true)
                    }}
                  >
                    <UserPlus className="size-3.5" />
                    Связать с пользователем
                  </Button>
                ) : (
                  <div className="text-sm text-faint">
                    Аккаунт не привязан к пользователю.
                  </div>
                )
              ) : (
                <div className="flex items-center gap-2 rounded-md border border-line bg-panel2/50 px-2.5 py-1.5">
                  <Link
                    to="/principals/$principalId"
                    params={{ principalId: account.principal_id }}
                    className="min-w-0 flex-1 truncate text-sm text-text transition-colors hover:text-accent"
                  >
                    {linkedPrincipal === null
                      ? shortId(account.principal_id)
                      : linkedPrincipal.display_name}
                  </Link>
                  {linkedPrincipal !== null && (
                    <PrincipalTypeChip type={linkedPrincipal.type} />
                  )}
                  {canMutateAccount && (
                    <UnlinkAccountButton
                      onClick={() => setUnlinkOpen(true)}
                    />
                  )}
                </div>
              )}
            </div>
          )}

          {connection.engine === 'postgres' && !sharedRole && (
            <AccountHBASection query={hbaQuery} identity={account.engine_identity} roles={hbaRoles} observedAt={connection.last_discovery_at} />
          )}

          <KeyValueList
            entries={[
              ...(sharedRole
                ? []
                : ([
                    ['auth scope', account.authentication_scope],
                    ['credential mode', account.credential_mode ?? '—'],
                    ['vault path', account.vault_path !== '' ? account.vault_path : '—'],
                  ] as Array<[string, string]>)),
              ['создан', formatDateTime(account.created_at)],
              // Tombstone: кто, когда и почему удалил. У старых tombstone'ов
              // (до ввода полей) известен максимум deleted_at; отсутствующие
              // значения показываем прочерком, причину — только когда есть.
              ...(alive
                ? []
                : ([
                    [
                      'удалён',
                      `${formatDateTime(account.deleted_at)} · ${account.deleted_by ?? '—'}`,
                    ],
                    ...(account.delete_reason != null && account.delete_reason !== ''
                      ? ([['причина', account.delete_reason]] as Array<
                          [string, string]
                        >)
                      : []),
                  ] as Array<[string, string]>)),
            ]}
          />

          <AttributesSection attributes={account.attributes} />

          {/*
            Раздел прав: свёрнутая сводка, раскрытый список с поиском и
            фильтрами, подробности по клику. Подписи приходят из нормализации
            адаптера, поэтому все семь движков выглядят одинаково.
          */}
          <AccountPermissionsSection
            bindings={connection.engine === 'postgres' ? withoutObjectPrivileges(bindingsQuery.data ?? [], permissionsById) : bindingsQuery.data ?? []}
            roleAssignmentsOnly={connection.engine === 'postgres'}
            expandRequest={directAccessRequest}
            summaryExtra={connection.engine === 'postgres' ? <span className="text-[11px] tabular-nums text-muted">{objectRecord(connection.topology).postgres_object_acl_version !== 1 ? 'Нет снимка ACL' : `Прямые: ${directObjectSummary(accountDirectObjectCount(account, bindingsQuery.data ?? [], permissionsById), connection.topology)}`}</span> : undefined}
            additionalContent={connection.engine === 'postgres' ? <PostgresObjectAccess account={account} connection={connection}
              permissions={permissions} bindings={bindingsQuery.data ?? []} resourcesById={resourcesById} expandRequest={directAccessRequest}
              pending={bindingsQuery.isPending} error={bindingsQuery.isError}
              onStarted={(id, label) => { onOperationStarted(id, label, 'access'); invalidate() }} /> : undefined}
            permissionsById={permissionsById}
            resourcesById={resourcesById}
            engine={connection.engine}
            accountLabel={account.engine_identity}
            onRevoke={
              canMutateAccount
                ? (binding) => {
                    setRevokeBinding(binding)
                    setRevokeOpen(true)
                  }
                : undefined
            }
            revokingId={
              revokeMutation.isPending
                ? (revokeMutation.variables?.binding.id ?? null)
                : null
            }
          />
        </div>
      </SidePanel>

      <ManageRolesDrawer
        open={rolesOpen && actions.grant}
        account={account}
        permissions={permissions.filter(p => !isPostgresObjectPrivilege(p))}
        bindings={withoutObjectPrivileges(bindingsQuery.data ?? [], permissionsById)}
        onClose={() => setRolesOpen(false)}
        onStarted={(operationId, changes) => {
          setRolesOpen(false)
          const added = changes.added.length
          const removed = changes.removed.length
          onOperationStarted(
            operationId,
            `Изменение ролей · +${added} / −${removed}: ${account.engine_identity}`,
            'access',
          )
          invalidate()
        }}
      />

      {rolePermission !== null && (
        <AssignSharedRoleDrawer
          open={assignRoleOpen && canAssignRole}
          roleAccount={account}
          permission={rolePermission}
          principals={principalsQuery.data ?? []}
          onClose={() => setAssignRoleOpen(false)}
          onStarted={(operationId, accountNames) => {
            setAssignRoleOpen(false)
            onOperationStarted(
              operationId,
              `Назначение роли ${rolePermission.name} · аккаунтов: ${accountNames.length}`,
              'access',
            )
            invalidate()
          }}
        />
      )}

      <ConfirmActionDialog
        open={revokeOpen && revokeBinding !== null && canMutateAccount}
        title="Снять роль"
        description={
          <div>
            <div>
              Роль <span className="font-mono text-text">{revokePermissionName}</span>{' '}
              будет снята с аккаунта{' '}
              <span className="font-mono text-text">{account.engine_identity}</span>.
              Изменение применит worker.
            </div>
            <AccessImpactPreview
              model={revokeAccessModel}
              roleName={revokePermissionName}
            />
          </div>
        }
        confirmLabel="Снять"
        danger
        rehearsal={{
          title: `Снятие роли ${revokePermissionName}`,
          detail: (
            <>
              После подтверждения worker снимет роль у аккаунта{' '}
              <span className="font-mono text-text">{account.engine_identity}</span>.
            </>
          ),
          impact: (
            <AccessImpactPreview
              model={revokeAccessModel}
              roleName={revokePermissionName}
            />
          ),
        }}
        pending={revokeMutation.isPending}
        onConfirm={() => {
          if (revokeBinding !== null) {
            revokeMutation.mutate({
              binding: revokeBinding,
              permissionName: revokePermissionName,
              dangerous:
                permissionsById.get(revokeBinding.permission_definition_id)?.dangerous === true,
            })
          }
        }}
        onClose={() => setRevokeOpen(false)}
      />

      <ConfirmActionDialog
        open={confirmOpen && confirmKind !== null && canMutateAccount}
        title={confirmKind !== null ? CONFIRM_COPY[confirmKind].title : ''}
        description={
          confirmKind !== null
            ? CONFIRM_COPY[confirmKind].describe(account.engine_identity)
            : ''
        }
        confirmLabel={confirmKind !== null ? CONFIRM_COPY[confirmKind].confirmLabel : ''}
        rehearsal={confirmKind !== null ? {
          title: CONFIRM_COPY[confirmKind].title,
          detail: CONFIRM_COPY[confirmKind].describe(account.engine_identity),
          impact: (
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
              <span>{connection.display_name}</span>
              <span>{environmentLabel(connection)}</span>
              <span className="font-mono text-text">{account.engine_identity}</span>
            </div>
          ),
        } : undefined}
        pending={lifecycleMutation.isPending}
        onConfirm={() => {
          if (confirmKind === 'attach') {
            lifecycleMutation.mutate({ kind: 'rotate', rotate: { attach: true } })
            return
          }
          if (confirmKind !== null) {
            lifecycleMutation.mutate({ kind: confirmKind })
          }
        }}
        onClose={() => setConfirmOpen(false)}
      />

      {rotateChoice !== null && (
        <RotateChoiceDialog
          open={rotateChoiceOpen && canMutateAccount}
          account={account}
          choice={rotateChoice}
          pending={lifecycleMutation.isPending || sharedRotateMutation.isPending}
          error={actionError}
          onSubmit={submitRotateChoice}
          onClose={() => setRotateChoiceOpen(false)}
        />
      )}

      <DeleteAccountDialog
        open={deleteOpen && actions.delete}
        account={account}
        pending={lifecycleMutation.isPending}
        impact={
          <AccessImpactPreview
            model={accessModel}
            accountName={account.engine_identity}
          />
        }
        onConfirm={(reason) => lifecycleMutation.mutate({ kind: 'delete', reason })}
        onClose={() => setDeleteOpen(false)}
      />

      <ConfirmActionDialog
        open={purgeOpen}
        title="Удалить аккаунт навсегда"
        danger
        description={
          <div>
            <div>
              Запись аккаунта{' '}
              <span className="font-mono text-text">{account.engine_identity}</span>{' '}
              будет полностью удалена из Grantor вместе с оставшимися bindings и
              собственным секретом Vault. Восстановить её после этого нельзя.
              Исторический audit сохранится. Если связанный глобальный пользователь
              уже offboarded и это его последний аккаунт, он также будет удалён.
              Пользователь с другими аккаунтами останется в Grantor.
            </div>
            <AccessImpactPreview
              model={accessModel}
              accountName={account.engine_identity}
            />
          </div>
        }
        confirmLabel="Удалить навсегда"
        pending={purgeMutation.isPending}
        onConfirm={() => purgeMutation.mutate()}
        onClose={() => setPurgeOpen(false)}
      />

      <ShareLinkDialog
        open={shareOpen && actions.share}
        share={share}
        onClose={() => setShareOpen(false)}
      />

      <AdoptAccountDialog
        readOnlyBindingsCount={(account.access_summary?.readonly_direct_bindings ?? 0) + (bindingsQuery.data ?? []).filter(b => b.desired_state === null && isActiveAccessBinding(b) && !bindingManagementEligible(b)).length}
        directBindingsCount={account.access_summary?.unmanaged_direct_bindings ?? 0}
        dangerousDirectBindingsCount={account.access_summary?.unmanaged_dangerous_direct_bindings ?? 0}
        open={adoptOpen && actions.adopt}
        account={account}
        unmanagedBindings={unmanagedBindings}
        permissionsById={permissionsById}
        onClose={() => setAdoptOpen(false)}
        onAdopted={(result) => {
          setAdoptOpen(false)
          setActionError(null)
          // 200-путь (metadata) — принято немедленно; 202-путь (generate/
          // password) — стандартное уведомление об операции, как у ротации.
          if (result.operationId === null) {
            onNotice(
              `Аккаунт ${account.engine_identity} принят под управление` +
                (result.adoptedBindings > 0
                  ? `, прав принято: ${result.adoptedBindings}`
                  : ''),
            )
          } else {
            onOperationStarted(
              result.operationId,
              `Принятие аккаунта ${account.engine_identity} под управление`,
              'account',
            )
          }
          invalidate()
        }}
      />

      <RestoreAccountDialog
        open={restoreOpen}
        account={account}
        connectionId={connection.id}
        connection={connection}
        onClose={() => setRestoreOpen(false)}
        onRestored={(operationId) => {
          setActionError(null)
          onNotice(
            `Операция ${shortId(operationId)} завершена: аккаунт ${account.engine_identity} восстановлен без прежних прав`,
          )
          invalidate()
        }}
      />

      <LinkPrincipalDialog
        open={linkOpen && canMutateAccount}
        account={account}
        connection={connection}
        lockedPrincipalId={linkIntent === 'managed' ? account.principal_id : null}
        initialMode={linkIntent}
        onClose={() => setLinkOpen(false)}
        onLinked={(principalName, mode, operationId) => {
          setLinkOpen(false)
          setActionError(null)
          if (mode === 'managed' && operationId !== undefined) {
            onOperationStarted(
              operationId,
              `Связь аккаунта ${account.engine_identity} с пользователем ${principalName}`,
              'account',
            )
          } else {
            onNotice(
              `Аккаунт ${account.engine_identity} связан с пользователем ${principalName} для учёта`,
            )
          }
          invalidateLink()
        }}
      />

      <ConfirmActionDialog
        open={unlinkOpen && canMutateAccount}
        title="Отвязать от пользователя"
        description={
          <>
            Аккаунт <span className="font-mono text-text">{account.engine_identity}</span>{' '}
            будет отвязан от пользователя{' '}
            <span className="text-text">
              {linkedPrincipal === null
                ? shortId(account.principal_id)
                : linkedPrincipal.display_name}
            </span>
            . Привязка хранится в метаданных control plane: учётная запись в целевой
            системе не изменится.
          </>
        }
        confirmLabel="Отвязать"
        pending={unlinkMutation.isPending}
        onConfirm={() => unlinkMutation.mutate()}
        onClose={() => setUnlinkOpen(false)}
      />
    </>
  )
}
