import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, RefreshCw } from '@project/ui/icons'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { api, ApiError } from '../lib/api'
import { formatDateTime } from '../lib/time'
import { personalAPIKeyMetadata } from '../lib/personal-api-keys'
import type { IssuePersonalAPIKeyResponse, PersonalAPIKey, PersonalAPIKeyRole, PersonalAPIKeysResponse } from '../lib/personal-api-keys'
import { Button, Combobox, CopyButton, Dialog, Field, Input, IconButton, Spinner } from '@project/ui'
import { StatusChip } from './ui/badge'

const ENDPOINT = '/api/v1/me/api-keys'
const DAY_MS = 24 * 60 * 60 * 1000
const ROLE_LABELS: Record<PersonalAPIKeyRole, string> = {
  viewer: 'Просмотр (viewer)',
  operator: 'Изменения (operator)',
  admin: 'Администрирование (admin)',
}

interface MyAPIKeysProps {
  onClose: () => void
}

/** Mounted only while open; the one-time value never enters a query or mutation. */
export function MyAPIKeys({ onClose }: MyAPIKeysProps) {
  const auth = useAuth()
  const queryClient = useQueryClient()
  const queryKey = ['personal-api-keys', auth.email, auth.role] as const
  const initialFocusRef = useRef<HTMLInputElement | null>(null)
  const secretFocusRef = useRef<HTMLParagraphElement | null>(null)
  const confirmationFocusRef = useRef<HTMLParagraphElement | null>(null)
  const mountedRef = useRef(true)
  const busyRef = useRef(false)
  const [pending, setPending] = useState<'issue' | 'revoke' | 'check' | null>(null)
  const [name, setName] = useState('')
  const [role, setRole] = useState<PersonalAPIKeyRole>('viewer')
  const [expiry, setExpiry] = useState('30')
  const [error, setError] = useState<string | null>(null)
  const [ownerChanged, setOwnerChanged] = useState(false)
  const [issued, setIssued] = useState<{ token: string; key: PersonalAPIKey } | null>(null)
  const [revokeKey, setRevokeKey] = useState<PersonalAPIKey | null>(null)
  const [uncertainIssue, setUncertainIssue] = useState<{ name: string; checked: boolean } | null>(null)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  useEffect(() => {
    if (issued !== null) secretFocusRef.current?.focus()
    else if (revokeKey !== null) confirmationFocusRef.current?.focus()
    else initialFocusRef.current?.focus()
  }, [issued, revokeKey])

  const keysQuery = useQuery({
    queryKey,
    gcTime: 0,
    retry: false,
    queryFn: async ({ signal }): Promise<PersonalAPIKeysResponse> => {
      const response = await api<PersonalAPIKeysResponse>(ENDPOINT, { signal })
      return {
        api_keys: response.api_keys.map(personalAPIKeyMetadata),
        user_id: response.user_id,
        max_expires_at: response.max_expires_at,
        allowed_roles: response.allowed_roles,
      }
    },
  })
  const metadata = keysQuery.data
  const keys = metadata?.api_keys ?? []
  const allowedRoles = (metadata?.allowed_roles ?? []).filter((candidate) =>
    roleAtLeast(auth.role, candidate),
  )
  const maxExpiresAt = Date.parse(metadata?.max_expires_at ?? '')
  const expiryOptions = [7, 30, 90]
    .filter((days) => Date.now() + days * DAY_MS <= maxExpiresAt)
    .map((days) => ({ value: String(days), label: `${days} дней` }))
  if (maxExpiresAt > Date.now()) {
    expiryOptions.push({ value: 'max', label: `До ${formatDateTime(metadata?.max_expires_at)}` })
  }
  const effectiveExpiry = expiryOptions.some((option) => option.value === expiry) ? expiry : 'max'
  const expiresAt = effectiveExpiry === 'max' ? maxExpiresAt : Date.now() + Number(effectiveExpiry) * DAY_MS
  const unresolvedKey = uncertainIssue !== null && keys.some((key) =>
    key.name === uncertainIssue.name && key.revoked_at === null && Date.parse(key.expires_at) > Date.now(),
  )
  const issueBlocked = uncertainIssue !== null && (!uncertainIssue.checked || unresolvedKey)
  const canIssue = metadata !== undefined && !ownerChanged && !keysQuery.isError && allowedRoles.includes(role) &&
    Number.isFinite(expiresAt) && expiresAt > Date.now() && !issueBlocked
  const nameTooLong = new TextEncoder().encode(name.trim()).length > 128

  const close = () => {
    if (busyRef.current) return
    if (revokeKey !== null) {
      setRevokeKey(null)
      setError(null)
      return
    }
    setIssued(null)
    onClose()
  }

  const issue = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const trimmedName = name.trim()
    if (busyRef.current || trimmedName === '' || nameTooLong || !canIssue) return
    busyRef.current = true
    setPending('issue')
    setError(null)
    try {
      const response = await api<IssuePersonalAPIKeyResponse>(ENDPOINT, {
        method: 'POST',
        body: { name: trimmedName, role, expires_at: new Date(expiresAt).toISOString() },
      })
      if (!mountedRef.current) return
      // A different browser tab may have replaced the cookie during the request.
      // Never display its one-time value under the previously loaded identity.
      if (response.api_key.user_id !== metadata?.user_id) {
        setOwnerChanged(true)
        setError('Учётная запись в браузере изменилась. Обновите страницу перед управлением API-ключами.')
        return
      }
      const key = personalAPIKeyMetadata(response.api_key)
      setIssued({ token: response.token, key })
      setName('')
      setUncertainIssue(null)
      queryClient.setQueryData<PersonalAPIKeysResponse>(queryKey, (current) =>
        current === undefined ? current : { ...current, api_keys: [key, ...current.api_keys] },
      )
      void queryClient.invalidateQueries({ queryKey })
    } catch (err: unknown) {
      if (!mountedRef.current) return
      if (!(err instanceof ApiError) || err.status === 0 || err.status >= 500) {
        setUncertainIssue({ name: trimmedName, checked: false })
        setError('Ответ о выпуске не получен. Проверьте список: ключ мог быть создан. Если он появился, отзовите его перед новым выпуском.')
      } else {
        setError('Не удалось выпустить ключ. Проверьте права и срок действия, затем обновите список.')
      }
    } finally {
      busyRef.current = false
      if (mountedRef.current) setPending(null)
    }
  }

  const checkList = async () => {
    if (busyRef.current || ownerChanged) return
    busyRef.current = true
    setPending('check')
    const result = await keysQuery.refetch()
    busyRef.current = false
    if (!mountedRef.current) return
    setPending(null)
    if (!result.isError) {
      setUncertainIssue((current) => current === null ? null : { ...current, checked: true })
    }
  }

  const revoke = async () => {
    if (busyRef.current || ownerChanged || revokeKey === null) return
    busyRef.current = true
    setPending('revoke')
    setError(null)
    try {
      await api(`${ENDPOINT}/${encodeURIComponent(revokeKey.id)}`, { method: 'DELETE' })
      if (!mountedRef.current) return
      const revokedId = revokeKey.id
      queryClient.setQueryData<PersonalAPIKeysResponse>(queryKey, (current) =>
        current === undefined ? current : {
          ...current,
          api_keys: current.api_keys.map((key) => key.id === revokedId ? { ...key, revoked_at: new Date().toISOString() } : key),
        },
      )
      setRevokeKey(null)
      void queryClient.invalidateQueries({ queryKey })
    } catch {
      if (mountedRef.current) setError('Не удалось подтвердить отзыв ключа. Проверьте список перед повторным действием.')
    } finally {
      busyRef.current = false
      if (mountedRef.current) setPending(null)
    }
  }

  const title = issued !== null ? 'Новый API-ключ' : revokeKey !== null ? 'Отозвать API-ключ' : 'Мои API-ключи'
  return (
    <Dialog open onClose={close} title={title} initialFocusRef={initialFocusRef} closeOnOverlayClick={pending === null}>
      {issued !== null ? (
        <div className="space-y-4">
          <p ref={secretFocusRef} tabIndex={-1} className="text-sm text-muted focus:outline-none">
            Ключ <span className="font-medium text-text">{issued.key.name}</span> для вашей учётки.
            Действует до {formatDateTime(issued.key.expires_at)}.
          </p>
          <div className="flex items-start gap-2">
            <code className="min-w-0 flex-1 break-all rounded-md border border-line bg-panel2 px-3 py-2 text-xs text-text">{issued.token}</code>
            <CopyButton value={issued.token} label="Копировать API-ключ" />
          </div>
          <p role="status" className="text-sm text-warn">
            Сохраните ключ до закрытия. Значение показывается один раз; восстановить его нельзя.
          </p>
          <p className="text-xs text-muted">Передавайте его в заголовке Authorization: Bearer. Права ограничены вашей учёткой и выбранной ролью.</p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={() => setIssued(null)}>К списку ключей</Button>
            <Button onClick={close}>Ключ сохранён, закрыть</Button>
          </div>
        </div>
      ) : revokeKey !== null ? (
        <div className="space-y-4" aria-busy={pending === 'revoke'}>
          <p ref={confirmationFocusRef} tabIndex={-1} className="text-sm text-muted focus:outline-none">Ключ <span className="font-medium text-text">{revokeKey.name}</span> немедленно перестанет действовать. Вернуть его нельзя.</p>
          {error !== null && <p role="alert" className="text-sm text-danger">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={close} disabled={pending !== null}>Отмена</Button>
            <Button variant="danger" onClick={() => { void revoke() }} disabled={pending !== null}>
              {pending === 'revoke' && <Spinner />}Отозвать
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <p className="text-sm text-muted">Ключи для API от имени <span className="break-all text-text">{auth.email}</span>. Они не дают больше прав, чем ваша учётка.</p>
          {error !== null && <p role="alert" className="text-sm text-danger">{error}</p>}
          <section aria-label="Выпущенные API-ключи" className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-text">Выпущенные ключи</h2>
              <Button variant="ghost" size="sm" onClick={() => { void checkList() }} disabled={pending !== null || ownerChanged}>
                <RefreshCw aria-hidden="true" className="size-3.5" />{uncertainIssue !== null ? 'Проверить список' : 'Обновить'}
              </Button>
            </div>
            {keysQuery.isPending ? <p role="status" className="flex items-center gap-2 text-sm text-muted"><Spinner />Загружаем ключи…</p>
              : keysQuery.isError ? <p role="alert" className="text-sm text-danger">Не удалось загрузить ключи. Обновите список.</p>
                : keys.length === 0 ? <p className="text-sm text-muted">У вас пока нет API-ключей.</p>
                  : <ul className="divide-y divide-line">
                    {keys.map((key) => {
                      const expired = Date.parse(key.expires_at) <= Date.now()
                      const revoked = key.revoked_at !== null
                      return (
                        <li key={key.id} className="flex items-start gap-3 py-3">
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="break-all text-sm font-medium text-text">{key.name}</span>
                              <StatusChip tone={revoked ? 'unmg' : expired ? 'warn' : 'ok'}>{revoked ? 'Отозван' : expired ? 'Истёк' : 'Действует'}</StatusChip>
                            </div>
                            <p className="text-xs text-muted">{ROLE_LABELS[key.role]} · до {formatDateTime(key.expires_at)}</p>
                            <p className="text-xs text-muted">Создан: {formatDateTime(key.created_at)} · использован: {formatDateTime(key.last_used_at)}</p>
                            {key.environments !== null && <p className="break-words text-xs text-muted">Окружения: {key.environments.join(', ')}</p>}
                          </div>
                          {!revoked && <IconButton label={`Отозвать ключ ${key.name}`} icon={<Ban aria-hidden="true" className="size-4" />} disabled={pending !== null || ownerChanged} onClick={() => { setRevokeKey(key); setError(null) }} />}
                        </li>
                      )
                    })}
                  </ul>}
          </section>
          <form onSubmit={(event) => { void issue(event) }} className="space-y-4 border-t border-line pt-4" autoComplete="off" aria-busy={pending === 'issue'}>
            <h2 className="text-sm font-semibold text-text">Выпустить API-ключ</h2>
            <Field label="Название ключа" hint={nameTooLong ? 'Сократите название ключа.' : 'Чтобы отличать ключи, например CI или локальный скрипт'}>
              <Input ref={initialFocusRef} value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" maxLength={128} required disabled={pending !== null} aria-invalid={nameTooLong || undefined} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Права ключа">
                <Combobox label="Права ключа" value={role} options={allowedRoles.map((value) => ({ value, label: ROLE_LABELS[value] }))} onValueChange={(value) => setRole(value as PersonalAPIKeyRole)} disabled={pending !== null || allowedRoles.length === 0} />
              </Field>
              <Field label="Срок действия">
                <Combobox label="Срок действия" value={effectiveExpiry} options={expiryOptions} onValueChange={setExpiry} disabled={pending !== null || expiryOptions.length === 0} />
              </Field>
            </div>
            {Number.isFinite(expiresAt) && <p className="text-xs text-muted">Действует до {formatDateTime(new Date(expiresAt).toISOString())}. Максимальный срок зависит от вашей сессии.</p>}
            {metadata !== undefined && expiryOptions.length === 0 && <p role="alert" className="text-sm text-danger">Сессия истекла. Войдите заново, чтобы выпустить ключ.</p>}
            {unresolvedKey && <p role="status" className="text-sm text-warn">Ключ с именем «{uncertainIssue?.name}» найден. Отзовите его перед повторным выпуском.</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button variant="outline" onClick={close} disabled={pending !== null}>Закрыть</Button>
              <Button type="submit" disabled={pending !== null || name.trim() === '' || nameTooLong || !canIssue}>
                {pending === 'issue' && <Spinner />}Выпустить ключ
              </Button>
            </div>
          </form>
        </div>
      )}
    </Dialog>
  )
}
