// Токены доступа сервис-принципала (admin): выпуск/список/отзыв service tokens
// (машинный доступ к API; ADR-0007, R10). Секция показывается только для
// principal type=service и роли admin (гейт на стороне вызова). Plaintext-токен
// (grt_…) возвращается сервером ровно один раз и показывается через
// OneTimeSecretDialog — после закрытия снова не отображается.
import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, KeyRound, Plus } from '@project/ui/icons'
import { api, apiDelete, apiPost, ApiError } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  IssueTokenResponse,
  ServiceToken,
  ServiceTokenList,
} from '../lib/types'
import { formatDateTime, formatRelative } from '../lib/time'
import {
  Button,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Dialog,
  Field,
  Input,
  Spinner,
  EmptyState,
  ErrorState,
  ErrorBanner,
  TableCopyableValue,
} from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { OneTimeSecretDialog } from '../components/ui/one-time-secret-dialog'
import { UI_COPY } from '../lib/ui-copy'

interface ServiceTokensSectionProps {
  principalId: string
  principalName: string
}

export function ServiceTokensSection(props: ServiceTokensSectionProps) {
  return <ServiceTokensPanel key={props.principalId} {...props} />
}

function ServiceTokensPanel({ principalId, principalName }: ServiceTokensSectionProps) {
  const queryClient = useQueryClient()
  const mountedRef = useRef(true)
  const issueBusyRef = useRef(false)

  const [issueOpen, setIssueOpen] = useState(false)
  const [name, setName] = useState('')
  const [allowConnectionCreation, setAllowConnectionCreation] = useState(false)
  // Выпущенный токен живёт только в состоянии до закрытия диалога показа;
  // повторный показ невозможен — нужен новый выпуск (новый секрет).
  const [issuedToken, setIssuedToken] = useState<IssueTokenResponse | null>(null)
  const [secretOpen, setSecretOpen] = useState(false)
  // Токен диалога отзыва хранится отдельно от флага open, чтобы контент не
  // исчезал во время exit-анимации.
  const [revokeToken, setRevokeToken] = useState<ServiceToken | null>(null)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  // Сброс поля имени при каждом открытии диалога выпуска.
  useEffect(() => {
    if (issueOpen) {
      setName('')
      setAllowConnectionCreation(false)
    }
  }, [issueOpen])

  const tokensQuery = useQuery({
    queryKey: qk.principalTokens(principalId),
    queryFn: async ({ signal }): Promise<ServiceTokenList> => {
      const data = await api<ServiceTokenList>(`/api/v1/principals/${principalId}/tokens`, { signal })
      return {
        tokens: data.tokens.map((token) => ({
          id: token.id, principal_id: token.principal_id, name: token.name,
          created_at: token.created_at, last_used_at: token.last_used_at,
          revoked_at: token.revoked_at, permissions: token.permissions ?? [],
        })),
      }
    },
  })

  const issueMutation = useMutation({
    gcTime: 0,
    retry: false,
    mutationFn: async (request: { name: string; permissions: string[] }) => {
      const data = await apiPost<IssueTokenResponse>(`/api/v1/principals/${principalId}/tokens`, request)
      if (data.principal_id !== principalId) throw new Error('Token owner changed; refresh the principal before issuing another token.')
      // Plaintext must not become mutation data, even before garbage collection.
      if (mountedRef.current) setIssuedToken(data)
      return { id: data.id, principal_id: data.principal_id, name: data.name, permissions: data.permissions ?? [] }
    },
    onSuccess: () => {
      if (!mountedRef.current) return
      setActionError(null)
      setIssueOpen(false)
      setSecretOpen(true)
      void queryClient.invalidateQueries({ queryKey: qk.principalTokens(principalId) })
    },
    onError: (err: unknown) => {
      if (!mountedRef.current) return
      setActionError(err instanceof ApiError && (err.status === 0 || err.status >= 500)
        ? 'Ответ о выпуске не получен. Проверьте список: токен мог быть создан. Отзовите его перед новым выпуском.'
        : 'Не удалось выпустить токен. Проверьте права и обновите список перед повторным действием.')
      void queryClient.invalidateQueries({ queryKey: qk.principalTokens(principalId) })
    },
    onSettled: () => { issueBusyRef.current = false },
  })

  const revokeMutation = useMutation({
    mutationFn: (token: ServiceToken) =>
      apiDelete<{ revoked: string }>(`/api/v1/tokens/${token.id}`),
    onSuccess: () => {
      setActionError(null)
      setRevokeOpen(false)
      void queryClient.invalidateQueries({ queryKey: qk.principalTokens(principalId) })
    },
    onError: (err: unknown) => {
      setRevokeOpen(false)
      setActionError(errorMessage(err))
    },
  })

  const tokens = tokensQuery.data?.tokens ?? []

  const issueButton = (
    <Button size="sm" onClick={() => setIssueOpen(true)}>
      <Plus className="size-4" />
      Выпустить токен
    </Button>
  )

  const submitIssue = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const trimmed = name.trim()
    if (trimmed === '' || issueBusyRef.current) {
      return
    }
    issueBusyRef.current = true
    issueMutation.mutate({ name: trimmed, permissions: allowConnectionCreation ? ['connections:create'] : [] })
  }

  const closeIssue = () => {
    if (!issueBusyRef.current) setIssueOpen(false)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-text">{UI_COPY.apiTokens}</h2>
          <p className="mt-0.5 text-xs text-faint">
            Машинный доступ к API Grantor от имени сервиса
          </p>
        </div>
        {issueButton}
      </div>

      {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}

      {tokensQuery.isError ? (
        <ErrorState
          message={errorMessage(tokensQuery.error)}
          onRetry={() => {
            void tokensQuery.refetch()
          }}
        />
      ) : tokensQuery.isPending ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : tokens.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="API-токенов нет"
          description="Выпустите API-токен для машинного доступа к Grantor от имени сервиса."
          action={issueButton}
        />
      ) : (
        <TableContainer>
          <Table>
            <TableHeader>
              <tr>
                <TableHead>Имя</TableHead>
                <TableHead>Создан</TableHead>
                <TableHead>Использован</TableHead>
                <TableHead>Статус</TableHead>
                <TableHead className="w-24 text-right">
                  <span className="sr-only">Действия</span>
                </TableHead>
              </tr>
            </TableHeader>
            <TableBody>
              {tokens.map((token) => {
                const revoked = token.revoked_at !== null
                return (
                  <TableRow key={token.id}>
                    <TableCell className="font-medium">
                      <TableCopyableValue
                        value={token.name}
                        label={`Копировать имя API-токена ${token.name}`}
                      />
                      {token.permissions.includes('connections:create') && (
                        <p className="mt-1 text-xs font-normal text-muted">Добавление подключений</p>
                      )}
                    </TableCell>
                    <TableCell className="text-muted" title={formatDateTime(token.created_at)}>
                      {formatRelative(token.created_at)}
                    </TableCell>
                    <TableCell className="text-muted" title={formatDateTime(token.last_used_at)}>
                      {formatRelative(token.last_used_at)}
                    </TableCell>
                    <TableCell>
                      <StatusChip tone={revoked ? 'unmg' : 'ok'}>
                        {revoked ? 'Revoked' : 'Active'}
                      </StatusChip>
                    </TableCell>
                    <TableCell className="text-right">
                      {!revoked && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setRevokeToken(token)
                            setRevokeOpen(true)
                          }}
                        >
                          <Ban className="size-3.5" />
                          Отозвать
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog open={issueOpen} onClose={closeIssue} closeOnOverlayClick={!issueMutation.isPending} title="Выпустить токен">
        <form onSubmit={submitIssue} className="space-y-4" autoComplete="off">
          <p className="text-sm text-muted">
            Токен даёт сервису{' '}
            <span className="text-text">{principalName}</span> машинный доступ к API.
            Значение показывается один раз при выпуске.
          </p>
          <Field label="Имя" hint="как токен будет виден в списке, например ci-deploy">
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ci-deploy"
              autoComplete="off"
              required
              disabled={issueMutation.isPending}
            />
          </Field>
          <div className="space-y-1.5">
            <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm text-text">
              <input
                type="checkbox"
                checked={allowConnectionCreation}
                onChange={(event) => setAllowConnectionCreation(event.target.checked)}
                disabled={issueMutation.isPending}
                className="accent-accent"
                aria-describedby="service-token-create-connection-hint"
              />
              Разрешить добавление подключений
            </label>
            <p id="service-token-create-connection-hint" className="text-xs text-muted">
              Только в разрешённых окружениях, с утверждённым источником credentials.
            </p>
          </div>
          {actionError !== null && <p role="alert" className="text-sm text-danger">{actionError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="outline"
              onClick={closeIssue}
              disabled={issueMutation.isPending}
            >
              Отмена
            </Button>
            <Button type="submit" disabled={issueMutation.isPending || name.trim() === ''}>
              {issueMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
              Выпустить
            </Button>
          </div>
        </form>
      </Dialog>

      <OneTimeSecretDialog
        open={secretOpen}
        title="API-токен"
        secret={issuedToken?.token ?? null}
        chips={<StatusChip tone="ok">One-time</StatusChip>}
        warning="Токен показан один раз и больше не отображается. Сохраните его сейчас."
        onClose={() => { setSecretOpen(false); setIssuedToken(null) }}
      />

      <ConfirmActionDialog
        open={revokeOpen && revokeToken !== null}
        title="Отозвать токен"
        description={
          revokeToken !== null ? (
            <>
              Токен <span className="text-text">{revokeToken.name}</span> будет
              немедленно отозван и перестанет действовать. Действие необратимо.
            </>
          ) : (
            ''
          )
        }
        confirmLabel="Отозвать"
        danger
        pending={revokeMutation.isPending}
        onConfirm={() => {
          if (revokeToken !== null) {
            revokeMutation.mutate(revokeToken)
          }
        }}
        onClose={() => setRevokeOpen(false)}
      />
    </div>
  )
}
