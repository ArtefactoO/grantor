// Экран «Пользователи»: список principals — людей и сервисов, к которым
// привязываются учётные записи подключений. Создание принципала
// (operator+) — метаданные control plane: worker не участвует, API
// отвечает 201 сразу. Строка таблицы ведёт на деталь принципала.
import { useEffect, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Users } from '@project/ui/icons'
import { api, apiList, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  CreatePrincipalRequest,
  DirectorySearchResponse,
  Principal,
  PrincipalType,
} from '../lib/types'
import { externalIdentity } from '../lib/externalIdentity'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
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
  ErrorBanner,
  RadioOptionCard,
  SearchInput,
  TableCopyableValue,
} from '@project/ui'
import { PrincipalTypeChip, PrincipalTypeIcon } from '../components/ui/badge'
import { DirectoryImportDialog } from '../components/directory-import-dialog'
import { QueryStates } from '../components/ui/query-states'
import { SegmentedFilter } from '../components/ui/selection-chips'
import { PrincipalProfileDrawer } from './principal-profile-drawer'
import { directoryFilterOptions } from '../lib/filter-presentation'
import type { DirectoryFilterValue } from '../lib/filter-presentation'
import { PrincipalIdentityChips } from '../components/principal-identity-chips'

export type PrincipalDirectoryView = DirectoryFilterValue | 'purging'

/**
 * Сколько дней осталось до необратимого удаления; null — срок не задан.
 * Округление вверх: «удалится через 1 день» честнее «через 0 дней».
 */
export function daysUntilPurge(purgeAfter: string | null | undefined, now: Date = new Date()): number | null {
  if (purgeAfter == null) return null
  const deadline = new Date(purgeAfter)
  if (Number.isNaN(deadline.getTime())) return null
  return Math.max(0, Math.ceil((deadline.getTime() - now.getTime()) / 86_400_000))
}

export interface PrincipalDirectoryProps {
  principals: Principal[]
  onOpen: (principalId: string) => void
  action?: ReactNode
}

/** Текущие, выводимые и удалённые пользователи не смешиваются в одном списке. */
export function PrincipalDirectory({ principals, onOpen, action }: PrincipalDirectoryProps) {
  const [view, setView] = useState<PrincipalDirectoryView>('current')
  const [search, setSearch] = useState('')
  const current = principals.filter(
    (principal) => principal.status !== 'deleted' && principal.status !== 'pending_purge',
  )
  // «На удалении»: доступ закрыт, данные целы, вывод ещё отменяется одной
  // кнопкой. Отдельная вкладка — иначе про окно отмены вспоминают, только
  // открыв конкретного пользователя.
  const purging = principals.filter((principal) => principal.status === 'pending_purge')
  const deleted = principals.filter((principal) => principal.status === 'deleted')
  const query = search.trim().toLocaleLowerCase()
  const viewItems = view === 'deleted' ? deleted : view === 'purging' ? purging : current
  const visible = viewItems.filter((principal) =>
    `${principal.display_name} ${externalIdentity(principal)} ${principal.external_provider} ${principal.external_subject}`
      .toLocaleLowerCase()
      .includes(query),
  )

  return (
    <div className="space-y-3">
      <div
        className="flex flex-wrap items-center gap-2"
        role="group"
        aria-label="Поиск и фильтры пользователей"
      >
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Имя или внешний идентификатор"
          ariaLabel="Поиск пользователей"
          density="compact"
          className="w-72 max-w-full shrink-0"
        />
        <SegmentedFilter
          label="Состояние пользователей"
          value={view}
          onChange={setView}
          options={[
            ...directoryFilterOptions(current.length, deleted.length).slice(0, 1),
            // Пустой чип «Offboarding 0» скрывается, как пустые фильтры
            // Контроля; активным он остаётся видимым вместе с результатом.
            ...(purging.length > 0 || view === 'purging'
              ? [{ value: 'purging' as const, label: 'Offboarding', count: purging.length }]
              : []),
            ...directoryFilterOptions(current.length, deleted.length).slice(1),
          ]}
        />
        {action !== undefined && <div className="ml-auto shrink-0">{action}</div>}
      </div>

      {view === 'deleted' && (
        <p className="text-sm text-muted">
          Удаление пользователя необратимо. Записи об удалении доступны только для
          аудита; восстановить пользователя или его прежние связи нельзя.
        </p>
      )}
      {view === 'purging' && (
        <p className="text-sm text-muted">
          Доступ этих пользователей закрыт, но данные целы: до истечения срока
          вывод отменяется одной кнопкой на карточке пользователя.
        </p>
      )}

      {visible.length === 0 ? (
        <EmptyState
          icon={Users}
          title={
            query !== ''
              ? 'Пользователи не найдены'
              : view === 'deleted'
                ? 'Удалённых пользователей нет'
                : 'Текущих пользователей нет'
          }
          description={
            query !== ''
              ? 'Измените поисковый запрос или состояние пользователей.'
              : view === 'deleted'
              ? 'Удалённые пользователи появятся здесь после удаления.'
              : 'Добавьте пользователя, чтобы назначать ему аккаунты подключений.'
          }
        />
      ) : (
        <TableContainer className="max-sm:overflow-x-visible max-sm:border-0 max-sm:bg-transparent">
          <Table className="max-sm:block max-sm:min-w-0">
            <TableHeader className="max-sm:sr-only">
              <tr>
                <TableHead>Login</TableHead>
                <TableHead>Тип</TableHead>
                <TableHead>Внешний идентификатор</TableHead>
                <TableHead>Аккаунты</TableHead>
                <TableHead>Identity и статус</TableHead>
              </tr>
            </TableHeader>
            <TableBody className="max-sm:block max-sm:space-y-2">
              {visible.map((principal) => (
                <TableRow
                  key={principal.id}
                  interaction="selectable"
                  className={`${view === 'deleted' ? 'opacity-60 ' : ''}max-sm:grid max-sm:grid-cols-1 max-sm:rounded-lg max-sm:border max-sm:border-line max-sm:bg-panel max-sm:px-3 max-sm:py-2`}
                  onClick={() => onOpen(principal.id)}
                >
                  <TableCell className="font-medium max-sm:grid max-sm:h-auto max-sm:grid-cols-[7rem_minmax(0,1fr)] max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:whitespace-normal">
                    <MobileFieldLabel>Login</MobileFieldLabel>
                    <span className="min-w-0">
                      <TableCopyableValue
                        value={principal.display_name}
                        label={`Копировать login ${principal.display_name}`}
                        valueClassName="font-mono text-sm font-medium text-text"
                      />
                      {view === 'purging' && (() => {
                        const days = daysUntilPurge(principal.purge_after)
                        return days === null ? null : (
                          <span className="block text-xs text-warn">
                            удалится безвозвратно через {days} дн.
                          </span>
                        )
                      })()}
                    </span>
                  </TableCell>
                  <TableCell className="max-sm:grid max-sm:h-auto max-sm:grid-cols-[7rem_minmax(0,1fr)] max-sm:items-start max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:whitespace-normal">
                    <MobileFieldLabel>Тип</MobileFieldLabel>
                    <span className="min-w-0">
                      <PrincipalTypeChip type={principal.type} />
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-[12px] text-muted max-sm:grid max-sm:h-auto max-sm:grid-cols-[7rem_minmax(0,1fr)] max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:whitespace-normal">
                    <MobileFieldLabel>Внешний ID</MobileFieldLabel>
                    <span className="min-w-0 break-all">{externalIdentity(principal)}</span>
                  </TableCell>
                  <TableCell className="tabular-nums max-sm:grid max-sm:h-auto max-sm:grid-cols-[7rem_minmax(0,1fr)] max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:whitespace-normal">
                    <MobileFieldLabel>Аккаунты</MobileFieldLabel>
                    <span>{principal.accounts_count ?? 0}</span>
                  </TableCell>
                  <TableCell className="max-sm:grid max-sm:h-auto max-sm:grid-cols-[7rem_minmax(0,1fr)] max-sm:items-start max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:whitespace-normal">
                    <MobileFieldLabel>Identity и статус</MobileFieldLabel>
                    <PrincipalIdentityChips principal={principal} className="min-w-0" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </div>
  )
}

function MobileFieldLabel({ children }: { children: string }) {
  return (
    <span className="text-xs font-medium text-faint sm:hidden" aria-hidden="true">
      {children}
    </span>
  )
}

export function PrincipalsPage() {
  const auth = useAuth()
  const canOperate = roleAtLeast(auth.role, 'operator')
  const [createOpen, setCreateOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [selectedPrincipalId, setSelectedPrincipalId] = useState<string | null>(null)

  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
  })

  const principals = principalsQuery.data ?? []
  const selectedPrincipal = principals.find(
    (principal) => principal.id === selectedPrincipalId,
  )

  // Заведение из каталога — основной путь там, где IdP подключён: человек
  // уже существует, и вводить его данные руками незачем. Кнопка скрывается,
  // если каталог не настроен: 501 от API об этом и сообщает.
  const directoryQuery = useQuery({
    queryKey: qk.directoryProbe(),
    queryFn: ({ signal }) =>
      api<DirectorySearchResponse>('/api/v1/directory/users?limit=1', { signal }),
    enabled: canOperate,
    retry: false,
    staleTime: 5 * 60_000,
  })
  const directoryAvailable = directoryQuery.isSuccess

  const createButton = canOperate ? (
    <span className="flex flex-wrap items-center gap-2">
      {directoryAvailable && (
        <Button size="sm" onClick={() => setImportOpen(true)}>
          <Users className="size-4" />
          Добавить из каталога
        </Button>
      )}
      <Button
        size="sm"
        variant={directoryAvailable ? 'outline' : 'primary'}
        onClick={() => setCreateOpen(true)}
      >
        <Plus className="size-4" />
        {directoryAvailable ? 'Завести вручную' : 'Добавить пользователя'}
      </Button>
    </span>
  ) : undefined

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <h1 className="text-lg font-semibold">Пользователи</h1>

      <QueryStates
        query={principalsQuery}
        empty={
          <EmptyState
            icon={Users}
            title="Пользователей пока нет"
            description="Добавьте пользователя, чтобы назначать ему аккаунты подключений."
            action={createButton}
          />
        }
      >
        {() => (
          <PrincipalDirectory
            principals={principals}
            onOpen={setSelectedPrincipalId}
            action={createButton}
          />
        )}
      </QueryStates>

      <CreatePrincipalDialog open={createOpen} onClose={() => setCreateOpen(false)} />
      <DirectoryImportDialog open={importOpen} onClose={() => setImportOpen(false)} />
      <PrincipalProfileDrawer
        principalId={selectedPrincipalId}
        principalName={selectedPrincipal?.display_name}
        onClose={() => setSelectedPrincipalId(null)}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Создание принципала: POST /api/v1/principals (operator+).

interface CreatePrincipalDialogProps {
  open: boolean
  onClose: () => void
}

interface PrincipalForm {
  type: PrincipalType
  displayName: string
  provider: string
  subject: string
}

const EMPTY_PRINCIPAL_FORM: PrincipalForm = {
  type: 'human',
  displayName: '',
  provider: '',
  subject: '',
}

function CreatePrincipalDialog({ open, onClose }: CreatePrincipalDialogProps) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<PrincipalForm>(EMPTY_PRINCIPAL_FORM)
  const [formError, setFormError] = useState<string | null>(null)

  // Сброс формы при каждом открытии диалога.
  useEffect(() => {
    if (open) {
      setForm(EMPTY_PRINCIPAL_FORM)
      setFormError(null)
    }
  }, [open])

  const setField = <K extends keyof PrincipalForm>(key: K, value: PrincipalForm[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const createMutation = useMutation({
    mutationFn: (payload: CreatePrincipalRequest) =>
      apiPost<Principal>('/api/v1/principals', payload),
    onSuccess: () => {
      setFormError(null)
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      onClose()
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err))
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const provider = form.provider.trim()
    const subject = form.subject.trim()
    // Зеркало валидации бэкенда: identity задаётся только парой.
    if ((provider === '') !== (subject === '')) {
      setFormError('external provider и subject задаются только парой')
      return
    }
    const payload: CreatePrincipalRequest = {
      type: form.type,
      display_name: form.displayName.trim(),
    }
    if (provider !== '') {
      payload.external_provider = provider
      payload.external_subject = subject
    }
    createMutation.mutate(payload)
  }

  return (
    <Dialog open={open} onClose={onClose} title="Новый пользователь">
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        <div>
          <span className="mb-1.5 block text-xs font-medium text-muted">Тип</span>
          <div className="space-y-1.5">
            <RadioOptionCard
              name="principal-type"
              label="Человек"
              hint="сотрудник с личными учётными записями"
              icon={<PrincipalTypeIcon type="human" />}
              checked={form.type === 'human'}
              onSelect={() => setField('type', 'human')}
            />
            <RadioOptionCard
              name="principal-type"
              label="Сервис"
              hint="приложение или автоматизация"
              icon={<PrincipalTypeIcon type="service" />}
              checked={form.type === 'service'}
              onSelect={() => setField('type', 'service')}
            />
          </div>
        </div>

        <Field label="Login" hint="как пользователь будет виден в списках и подключениях">
          <Input
            value={form.displayName}
            onChange={(e) => setField('displayName', e.target.value)}
            placeholder="ivan.petrov"
            className="font-mono text-[13px]"
            autoComplete="off"
            required
          />
        </Field>

        <div className="space-y-3 rounded-md border border-line bg-panel2/50 p-3">
          <div className="text-xs font-medium text-muted">
            External identity: необязательно, задаётся только парой
          </div>
          <p className="text-xs text-faint">
            Пользователи каталога (Authentik) так не заводятся. Добавляйте их
            через «Добавить из каталога»: импорт сверяет subject и сразу
            получает статус.
          </p>
          <Field label="Provider" hint="источник identity, например keycloak">
            <Input
              value={form.provider}
              onChange={(e) => setField('provider', e.target.value)}
              placeholder="keycloak"
              className="font-mono text-[13px]"
              autoComplete="off"
            />
          </Field>
          <Field label="Subject" hint="subject в источнике, например email">
            <Input
              value={form.subject}
              onChange={(e) => setField('subject', e.target.value)}
              placeholder="ivan.petrov@example.com"
              className="font-mono text-[13px]"
              autoComplete="off"
            />
          </Field>
        </div>

        <p className="text-xs text-muted">
          Пароль здесь не создаётся: credential конкретного окружения появится при
          первой выдаче доступа или действии «Связать и управлять».
        </p>

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose} disabled={createMutation.isPending}>
            Отмена
          </Button>
          <Button type="submit" disabled={createMutation.isPending}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Добавить
          </Button>
        </div>
      </form>
    </Dialog>
  )
}
