// Действия экрана «Пользователь»: мутации включения/отключения (каскад по
// managed-аккаунтам), необратимого offboard, отвязки аккаунта, ротации и
// выдачи общего пароля окружения, вместе с их инвалидацией кэша и
// состоянием сопутствующих диалогов/ошибок. Каскадные ответы (202) несут
// operation_id — он выставляется в cascadeOperationId, страница показывает
// панель bulk-операции.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiDelete, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  Account,
  PrincipalOffboardResponse,
  PrincipalCredentialCreateResponse,
  PrincipalRotateResponse,
  PrincipalStatusResponse,
  ShareCredentialResponse,
} from '../lib/types'
import { shortId } from '../lib/status'

/** Направление каскадного изменения статуса принципала. */
export type PrincipalStatusKind = 'disable' | 'enable'

/** Длительность окна отмены вывода из системы, секунд. */
export const OFFBOARD_COUNTDOWN_SECONDS = 6
export interface CreatePrincipalCredentialInput {
  environment: string
  mode: 'generated' | 'provided'
  password?: string
}

export function usePrincipalActions(principalId: string) {
  const queryClient = useQueryClient()

  // Аккаунт диалога отвязки хранится отдельно от флага open, чтобы
  // контент не исчезал во время exit-анимации.
  const [unlinkAccount, setUnlinkAccount] = useState<Account | null>(null)
  const [unlinkOpen, setUnlinkOpen] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // Confirm-диалог каскадного disable/enable (kind хранится отдельно от
  // открытости, как unlinkAccount) и danger-диалог offboard.
  const [statusConfirm, setStatusConfirm] = useState<PrincipalStatusKind | null>(null)
  const [offboardOpen, setOffboardOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [purgeOpen, setPurgeOpen] = useState(false)
  // Каскадная bulk-операция (disable/enable/offboard) для панели операции.
  const [cascadeOperationId, setCascadeOperationId] = useState<string | null>(null)

  // Диалоги ротации и выдачи кредов и данные одноразовой ссылки (живут
  // только в состоянии до закрытия диалога).
  const [rotateOpen, setRotateOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  const [shareLink, setShareLink] = useState<ShareCredentialResponse | null>(null)
  const [shareLinkOpen, setShareLinkOpen] = useState(false)
  const [createCredentialOpen, setCreateCredentialOpen] = useState(false)

  const statusMutation = useMutation({
    mutationFn: (kind: PrincipalStatusKind) =>
      apiPost<PrincipalStatusResponse>(`/api/v1/principals/${principalId}/${kind}`),
    onSuccess: (data, kind) => {
      setActionError(null)
      setStatusConfirm(null)
      if (data.operation_id !== undefined) {
        setCascadeOperationId(data.operation_id)
        setNotice(
          `Операция ${shortId(data.operation_id)} запущена: ${
            kind === 'disable'
              ? 'отключение аккаунтов во всех кластерах'
              : 'включение аккаунтов во всех кластерах'
          }`,
        )
      }
      // Префикс ['principals'] накрывает и список, и деталь.
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setStatusConfirm(null)
      setActionError(errorMessage(err))
    },
  })

  // Согласие принять под управление пароли, которыми grantor не владеет:
  // живёт рядом с диалогом, сбрасывается при каждом его открытии, чтобы
  // прошлый выбор не переносился на следующего пользователя.
  const [offboardTakeover, setOffboardTakeover] = useState(false)

  // Окно отмены между подтверждением и запросом (решение пользователя):
  // ротация паролей необратима и исполняется через секунды после запроса,
  // поэтому промах должен ловиться ДО отправки, а не отменяться restore —
  // тот вернёт права, но не старые пароли. Пока секунды идут, на сервер не
  // уходит ничего: закрытие вкладки просто отменяет вывод (в безопасную
  // сторону). null — окно не открыто.
  const [offboardCountdown, setOffboardCountdown] = useState<number | null>(null)
  const offboardTimers = useRef<{ fire?: number; tick?: number }>({})

  const clearOffboardTimers = useCallback(() => {
    window.clearTimeout(offboardTimers.current.fire)
    window.clearInterval(offboardTimers.current.tick)
    offboardTimers.current = {}
  }, [])

  const offboardMutation = useMutation({
    mutationFn: (takeover: boolean) =>
      apiPost<PrincipalOffboardResponse>(
        `/api/v1/principals/${principalId}/offboard?confirm=true`,
        { takeover_credentials: takeover },
      ),
    onSuccess: (data) => {
      setActionError(null)
      setOffboardOpen(false)
      const skipped = data.credential_takeover_required ?? []
      if (data.operation_id !== undefined) {
        setCascadeOperationId(data.operation_id)
        setNotice(
          skipped.length > 0
            ? `Операция ${shortId(data.operation_id)} запущена: offboarding пользователя. ` +
              `Пароли ${skipped.length} аккаунтов не менялись: grantor ими не владеет`
            : `Операция ${shortId(data.operation_id)} запущена: offboarding пользователя`,
        )
      } else {
        setNotice('Пользователь offboarded: управляемых аккаунтов не было')
      }
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setOffboardOpen(false)
      setActionError(errorMessage(err))
    },
  })

  // armOffboard закрывает диалог и открывает окно отсчёта; запрос уходит
  // только по его истечении. cancelOffboard закрывает окно без запроса.
  const armOffboard = useCallback((takeover: boolean) => {
    clearOffboardTimers()
    setOffboardOpen(false)
    setOffboardCountdown(OFFBOARD_COUNTDOWN_SECONDS)
    offboardTimers.current.tick = window.setInterval(() => {
      setOffboardCountdown((s) => (s === null || s <= 1 ? s : s - 1))
    }, 1000)
    offboardTimers.current.fire = window.setTimeout(() => {
      clearOffboardTimers()
      setOffboardCountdown(null)
      offboardMutation.mutate(takeover)
    }, OFFBOARD_COUNTDOWN_SECONDS * 1000)
  }, [clearOffboardTimers, offboardMutation])

  const cancelOffboard = useCallback(() => {
    clearOffboardTimers()
    setOffboardCountdown(null)
    setNotice('Вывод из системы отменён. Ничего не изменилось')
  }, [clearOffboardTimers])

  // Размонтирование страницы гасит таймеры: полузаряженный вывод не должен
  // выстрелить из фонового замыкания по уже закрытой карточке.
  useEffect(() => clearOffboardTimers, [clearOffboardTimers])

  // Отмена вывода из системы: обратная операция, а не откат — попадает в
  // audit наравне с offboard.
  const restoreMutation = useMutation({
    mutationFn: () => apiPost<PrincipalStatusResponse>(`/api/v1/principals/${principalId}/restore`),
    onSuccess: (data) => {
      setActionError(null)
      setRestoreOpen(false)
      if (data.operation_id !== undefined) {
        setCascadeOperationId(data.operation_id)
        setNotice(`Вывод отменён: аккаунты включаются обратно`)
      } else {
        setNotice('Вывод из системы отменён')
      }
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setRestoreOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const purgeMutation = useMutation({
    mutationFn: () =>
      apiDelete<{ principal_id: string; purged: true }>(
        `/api/v1/principals/${principalId}/purge`,
        { confirm: 'true' },
      ),
    onSuccess: () => {
      setActionError(null)
      setPurgeOpen(false)
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setPurgeOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const unlinkMutation = useMutation({
    mutationFn: (account: Account) =>
      apiPost<Account>(`/api/v1/accounts/${account.id}/unlink`),
    onSuccess: (updated) => {
      setActionError(null)
      setUnlinkOpen(false)
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({
        queryKey: qk.connectionAccounts(updated.connection_id),
      })
    },
    onError: (err: unknown) => {
      setUnlinkOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (environment: string) =>
      apiPost<PrincipalRotateResponse>(
        `/api/v1/principals/${principalId}/rotate?environment=${encodeURIComponent(environment)}`,
      ),
    onSuccess: (data, environment) => {
      setActionError(null)
      setRotateOpen(false)
      // Итог показывает панель операции: одна строка «запущена» оставляла
      // неизвестным, дошла ли ротация до целевых систем.
      setCascadeOperationId(data.operation_id)
      setNotice(
        `Ротация пароля в окружении ${environment} запущена. Статусы по подключениям ниже`,
      )
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (err: unknown) => {
      setRotateOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const shareMutation = useMutation({
    mutationFn: (environment: string) =>
      apiPost<ShareCredentialResponse>(
        `/api/v1/principals/${principalId}/share?environment=${encodeURIComponent(environment)}`,
      ),
    onSuccess: (data) => {
      setActionError(null)
      setShareOpen(false)
      setShareLink(data)
      setShareLinkOpen(true)
    },
    onError: (err: unknown) => {
      setShareOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const createCredentialMutation = useMutation({
    mutationFn: (input: CreatePrincipalCredentialInput) =>
      apiPost<PrincipalCredentialCreateResponse>(
        `/api/v1/principals/${principalId}/credentials`,
        input,
      ),
    onSuccess: (data) => {
      setActionError(null)
      setCreateCredentialOpen(false)
      setNotice(
        data.created
          ? `Credential для окружения ${data.environment} создан в Vault`
          : `Credential для окружения ${data.environment} уже был настроен`,
      )
      void queryClient.invalidateQueries({ queryKey: qk.principalCredentials(principalId) })
    },
    onError: (err: unknown) => {
      setCreateCredentialOpen(false)
      setActionError(errorMessage(err))
    },
  })

  return {
    unlinkAccount,
    setUnlinkAccount,
    unlinkOpen,
    setUnlinkOpen,
    actionError,
    setActionError,
    notice,
    setNotice,
    statusConfirm,
    setStatusConfirm,
    offboardOpen,
    setOffboardOpen,
    offboardTakeover,
    setOffboardTakeover,
    offboardCountdown,
    armOffboard,
    cancelOffboard,
    purgeOpen,
    setPurgeOpen,
    cascadeOperationId,
    setCascadeOperationId,
    rotateOpen,
    setRotateOpen,
    shareOpen,
    setShareOpen,
    shareLink,
    shareLinkOpen,
    setShareLinkOpen,
    statusMutation,
    offboardMutation,
    restoreOpen,
    setRestoreOpen,
    restoreMutation,
    purgeMutation,
    unlinkMutation,
    rotateMutation,
    shareMutation,
    createCredentialOpen,
    setCreateCredentialOpen,
    createCredentialMutation,
  }
}
