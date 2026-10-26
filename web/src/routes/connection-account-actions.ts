// Действия панели выбранного аккаунта: мутации unlink/share/revoke/lifecycle
// с их инвалидацией кэша и состоянием диалогов/ошибок. Панель
// (connection-account-panel) — тонкий рендер поверх этого хука.
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiDelete, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  BulkCreateBindingsResponse,
  Account,
  AccountOperationResponse,
  Binding,
  BindingOperationResponse,
  RotateAccountRequest,
  SharedCredentialChoice,
  ShareCredentialResponse,
} from '../lib/types'
import type { OperationAnchor } from '../components/operation-progress-notice'
import { useToast } from '@project/ui'
import { SHARED_CREDENTIAL_MODE } from './principal-detail-shared'
import { sharedCredentialChoice } from './connection-account-rotate'
import type { RotateChoice } from './connection-account-rotate'

export type LifecycleKind = 'disable' | 'enable' | 'rotate' | 'delete'

// Подписи запущенных lifecycle-операций для инлайн-уведомления.
const LIFECYCLE_NOTICE: Record<LifecycleKind, string> = {
  disable: 'отключение аккаунта',
  enable: 'включение аккаунта',
  rotate: 'ротация credential',
  delete: 'удаление аккаунта',
}

// Confirm-диалоги: rotate — обычная ротация аккаунта с личным паролем;
// attach — возврат отвязанного аккаунта на общий пароль пользователя.
export type ConfirmKind = Exclude<LifecycleKind, 'delete'> | 'attach'

// Владеет мутациями действий над аккаунтом, их инвалидацией кэша и
// состоянием сопутствующих диалогов/ошибок. Ключи invalidateQueries и тела
// мутаций совпадают с прежней реализацией панели один в один.
/** Переменные отзыва роли: dangerous решает, предлагать ли отмену в один клик. */
export interface RevokeVariables {
  binding: Binding
  permissionName: string
  dangerous: boolean
}

export function useAccountActions(
  account: Account,
  connectionId: string,
  onNotice: (text: string) => void,
  onOperationStarted: (operationId: string, label: string, anchor?: OperationAnchor) => void,
  onPurged?: () => void,
) {
  const queryClient = useQueryClient()
  const toast = useToast()

  // Данные диалогов (binding, ссылка, вид confirm) хранятся отдельно от
  // флагов open, чтобы контент не исчезал во время exit-анимации.
  const [rolesOpen, setRolesOpen] = useState(false)
  const [revokeBinding, setRevokeBinding] = useState<Binding | null>(null)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [share, setShare] = useState<ShareCredentialResponse | null>(null)
  const [shareOpen, setShareOpen] = useState(false)
  const [confirmKind, setConfirmKind] = useState<ConfirmKind | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [purgeOpen, setPurgeOpen] = useState(false)
  const [linkOpen, setLinkOpen] = useState(false)
  const [unlinkOpen, setUnlinkOpen] = useState(false)
  const [adoptOpen, setAdoptOpen] = useState(false)
  // Контекст выбора ротации приходит из 409 бэкенда и живёт отдельно от
  // флага open, чтобы диалог не пустел во время exit-анимации.
  const [rotateChoice, setRotateChoice] = useState<SharedCredentialChoice | null>(null)
  const [rotateChoiceOpen, setRotateChoiceOpen] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const invalidate = () => {
    void queryClient.invalidateQueries({
      queryKey: qk.connectionAccounts(connectionId),
    })
    void queryClient.invalidateQueries({ queryKey: qk.accountBindings(account.id) })
    void queryClient.invalidateQueries({ queryKey: qk.operations() })
  }

  // Привязка/отвязка — метаданные control plane: worker и операции не
  // участвуют, обновляем только аккаунты подключения и principals.
  const invalidateLink = () => {
    void queryClient.invalidateQueries({
      queryKey: qk.connectionAccounts(connectionId),
    })
    void queryClient.invalidateQueries({ queryKey: qk.principals() })
  }

  const unlinkMutation = useMutation({
    mutationFn: () => apiPost<Account>(`/api/v1/accounts/${account.id}/unlink`),
    onSuccess: () => {
      setActionError(null)
      setUnlinkOpen(false)
      onNotice(`Аккаунт ${account.engine_identity} отвязан от пользователя`)
      invalidateLink()
    },
    onError: (err: unknown) => {
      setUnlinkOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const shareMutation = useMutation({
    mutationFn: () =>
      apiPost<ShareCredentialResponse>(`/api/v1/accounts/${account.id}/share`),
    onSuccess: (data) => {
      setActionError(null)
      setShare(data)
      setShareOpen(true)
    },
    onError: (err: unknown) => {
      setActionError(errorMessage(err))
    },
  })

  // Возврат роли после отзыва — не откат, а обратная операция: она так же
  // исполняется worker'ом и так же попадает в аудит.
  const undoRevokeMutation = useMutation({
    mutationFn: ({ binding }: RevokeVariables) =>
      apiPost<BulkCreateBindingsResponse>('/api/v1/bindings/bulk', {
        items: [{
          account_id: binding.account_id,
          permission_id: binding.permission_definition_id,
          ...(binding.scope_resource_id === null ? {} : { scope_resource_id: binding.scope_resource_id }),
        }],
      }),
    onSuccess: (data, { permissionName }) => {
      onOperationStarted(data.operation_id, `Возврат роли ${permissionName}`, 'access')
      invalidate()
    },
    onError: (err: unknown) => setActionError(errorMessage(err)),
  })

  const revokeMutation = useMutation({
    mutationFn: ({ binding }: RevokeVariables) =>
      apiDelete<BindingOperationResponse>(`/api/v1/bindings/${binding.id}`),
    onSuccess: (data, variables) => {
      setActionError(null)
      setRevokeOpen(false)
      onOperationStarted(data.operation_id, `Снятие роли ${variables.permissionName}`, 'access')
      invalidate()
      toast.show({
        message: `Роль ${variables.permissionName} снята`,
        // Опасное право возвращается только обычным путём: там есть
        // предупреждение и подтверждение, которых в один клик быть не должно.
        action: variables.dangerous
          ? undefined
          : { label: 'Вернуть', onAct: () => undoRevokeMutation.mutate(variables) },
      })
    },
    onError: (err: unknown) => {
      setRevokeOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const lifecycleMutation = useMutation({
    // reason — необязательная причина удаления (только kind='delete'):
    // уходит JSON-телом DELETE-запроса; пустая/пробельная строка не
    // отправляется — бэкенд трактует её как «без причины».
    // rotate — необязательное намерение ротации (detach/attach).
    mutationFn: ({
      kind,
      reason,
      rotate,
    }: {
      kind: LifecycleKind
      reason?: string
      rotate?: RotateAccountRequest
    }) => {
      if (kind === 'delete') {
        const trimmed = reason?.trim() ?? ''
        return apiDelete<AccountOperationResponse>(
          `/api/v1/accounts/${account.id}`,
          { confirm: 'true' },
          trimmed !== '' ? { reason: trimmed } : undefined,
        )
      }
      return apiPost<AccountOperationResponse>(
        `/api/v1/accounts/${account.id}/${kind}`,
        rotate,
      )
    },
    onSuccess: (data, { kind }) => {
      setActionError(null)
      setConfirmOpen(false)
      setDeleteOpen(false)
      setRotateChoiceOpen(false)
      onOperationStarted(data.operation_id, LIFECYCLE_NOTICE[kind], 'account')
      invalidate()
    },
    onError: (err: unknown, { kind }) => {
      // Отказ «нужен осознанный выбор» — не ошибка, а ветка сценария:
      // бэкенд прислал контекст, по которому строится диалог выбора.
      const choice = kind === 'rotate' ? sharedCredentialChoice(err) : null
      if (choice !== null) {
        setActionError(null)
        setRotateChoice(choice)
        setRotateChoiceOpen(true)
        return
      }
      setConfirmOpen(false)
      setDeleteOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const purgeMutation = useMutation({
    mutationFn: () =>
      apiDelete<{ account_id: string; purged: true; principal_purged: boolean }>(
        `/api/v1/accounts/${account.id}/purge`,
        { confirm: 'true' },
      ),
    onSuccess: (data) => {
      setActionError(null)
      setPurgeOpen(false)
      onNotice(
        data.principal_purged
          ? `Аккаунт ${account.engine_identity} и связанный пользователь удалены из Grantor навсегда`
          : `Аккаунт ${account.engine_identity} удалён из Grantor навсегда`,
      )
      onPurged?.()
      void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setPurgeOpen(false)
      setActionError(errorMessage(err))
    },
  })

  // Ротация общего пароля пользователя: одна операция на окружение,
  // затрагивает все его аккаунты там. confirm обязателен, когда затронутых
  // аккаунтов больше серверного порога (см. RotateChoiceDialog).
  const sharedRotateMutation = useMutation({
    mutationFn: ({ choice, confirmed }: { choice: SharedCredentialChoice; confirmed: boolean }) =>
      apiPost<{ operation_id: string }>(
        `/api/v1/principals/${choice.principal_id}/rotate?environment=${encodeURIComponent(choice.environment)}`,
        { confirm: confirmed },
      ),
    onSuccess: (data, { choice }) => {
      setActionError(null)
      setRotateChoiceOpen(false)
      onOperationStarted(
        data.operation_id,
        `ротация общего пароля пользователя (аккаунтов: ${choice.affected_accounts})`,
        'account',
      )
      invalidate()
    },
    onError: (err: unknown) => {
      setActionError(errorMessage(err))
    },
  })

  const openConfirm = (kind: ConfirmKind) => {
    setConfirmKind(kind)
    setConfirmOpen(true)
  }

  // Ротация из панели. Аккаунт на общем пароле пользователя ведёт в диалог
  // выбора, остальные — в прежний короткий confirm без лишнего клика.
  // Признак «на общем пароле» подтверждает бэкенд: запрос без намерения
  // безопасен (он ничего не меняет) и приносит актуальный контекст выбора
  // вместе с серверным порогом подтверждения.
  const startRotate = () => {
    if (account.credential_mode === SHARED_CREDENTIAL_MODE) {
      lifecycleMutation.mutate({ kind: 'rotate' })
      return
    }
    openConfirm('rotate')
  }

  // Выбор в диалоге: сменить общий пароль либо отвязать этот аккаунт.
  const submitRotateChoice = (selected: RotateChoice, confirmed: boolean) => {
    if (rotateChoice === null) {
      return
    }
    if (selected === 'shared') {
      sharedRotateMutation.mutate({ choice: rotateChoice, confirmed })
      return
    }
    lifecycleMutation.mutate({ kind: 'rotate', rotate: { detach: true } })
  }

  return {
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
  }
}
