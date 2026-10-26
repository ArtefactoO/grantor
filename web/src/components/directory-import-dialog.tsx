// Заведение людей из внешнего каталога (Authentik/AD).
//
// Один диалог на оба режима, потому что это одно и то же действие с разным
// охватом: найти человека и добавить его — частный случай загрузки по
// списку. Разводить их по разным экранам значило бы заставлять оператора
// выбирать инструмент до того, как он понял, скольких ему нужно.
//
// По умолчанию — точечный режим: оператор ищет и отмечает нужных. Массовая
// загрузка спрятана за отдельным действием и доступна только админу: она
// создаёт произвольное число принципалов одним нажатием.
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Users } from '@project/ui/icons'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type {
  DirectoryCandidate,
  DirectoryImportResponse,
  DirectorySearchResponse,
} from '../lib/types'
import { useAuth, roleAtLeast } from '../auth/AuthProvider'
import { plural } from '../lib/plural'
import { cn, Button, Drawer, ErrorBanner, InlineNotice, SearchInput, Spinner } from '@project/ui'

const PLURAL_PEOPLE = ['человек', 'человека', 'человек'] as const

export interface DirectoryImportDialogProps {
  open: boolean
  onClose: () => void
  /** Вызывается после успешного импорта — обновить списки принципалов. */
  onImported?: () => void
}

export function DirectoryImportDialog({ open, onClose, onImported }: DirectoryImportDialogProps) {
  const { role } = useAuth()
  const queryClient = useQueryClient()
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<DirectoryImportResponse | null>(null)

  const canImportAll = roleAtLeast(role, 'admin')

  const searchQuery = useQuery({
    queryKey: qk.directorySearch(query),
    queryFn: ({ signal }) =>
      api<DirectorySearchResponse>(
        `/api/v1/directory/users?limit=50${query === '' ? '' : `&query=${encodeURIComponent(query)}`}`,
        { signal },
      ),
    enabled: open,
    // Каталог живёт своей жизнью; держать его ответ в кэше надолго незачем.
    staleTime: 30_000,
  })

  const candidates = searchQuery.data?.candidates ?? []
  // Уже заведённых выбирать нечего: показываем, но не даём отметить.
  const selectable = useMemo(() => candidates.filter((c) => !c.imported), [candidates])

  const importMutation = useMutation({
    mutationFn: (body: { subjects?: string[]; all?: boolean; query?: string; limit?: number }) =>
      api<DirectoryImportResponse>('/api/v1/directory/import', { method: 'POST', body }),
    onSuccess: (data) => {
      setResult(data)
      setSelected(new Set())
      setError(null)
      void queryClient.invalidateQueries({ queryKey: ['directory'] })
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      onImported?.()
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : 'Не удалось импортировать')
      setResult(null)
    },
  })

  const toggle = (subject: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(subject)) next.delete(subject)
      else next.add(subject)
      return next
    })
  }

  const close = () => {
    setQuery('')
    setSelected(new Set())
    setError(null)
    setResult(null)
    onClose()
  }

  return (
    <Drawer
      open={open}
      onClose={close}
      title="Добавить из каталога"
      description="Люди заводятся как пользователи grantor; доступы выдаются отдельно"
    >
      <div className="space-y-3">
        <SearchInput
          value={query}
          onChange={(next) => {
            setQuery(next)
            setResult(null)
          }}
          placeholder="Имя или адрес; пусто: весь каталог"
          ariaLabel="Поиск в каталоге"
        />

        {searchQuery.isError && (
          <ErrorBanner>
            Каталог недоступен: {(searchQuery.error as Error).message}
          </ErrorBanner>
        )}
        {error !== null && <ErrorBanner>{error}</ErrorBanner>}

        {result !== null && (
          <InlineNotice text={importResultText(result)} onClose={() => setResult(null)} />
        )}

        {searchQuery.isPending ? (
          <div className="flex items-center gap-2 text-xs text-muted">
            <Spinner className="size-3.5" /> Читаем каталог…
          </div>
        ) : candidates.length === 0 ? (
          <p className="text-xs text-muted">
            {query === '' ? 'Каталог пуст' : 'Никого не найдено'}
          </p>
        ) : (
          <>
            {/*
              Предел выдачи называется прямо: список может быть обрезан, и
              оператор должен понимать, что видит не весь каталог.
            */}
            {candidates.length >= (searchQuery.data?.limit ?? 0) && (
              <p className="text-[11px] text-muted">
                Показаны первые {searchQuery.data?.limit}. Уточните запрос, чтобы найти
                нужного человека.
              </p>
            )}
            <ul className="space-y-1">
              {candidates.map((candidate) => (
                <CandidateRow
                  key={candidate.subject}
                  candidate={candidate}
                  checked={selected.has(candidate.subject)}
                  onToggle={() => toggle(candidate.subject)}
                />
              ))}
            </ul>
          </>
        )}

        <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
          <Button
            onClick={() => importMutation.mutate({ subjects: [...selected] })}
            disabled={selected.size === 0 || importMutation.isPending}
          >
            {importMutation.isPending ? <Spinner className="size-3.5" /> : <Users className="size-3.5" />}
            Добавить{selected.size > 0 ? ` (${selected.size})` : ''}
          </Button>

          {canImportAll && (
            <Button
              variant="outline"
              onClick={() => importMutation.mutate({ all: true, query, limit: 500 })}
              disabled={importMutation.isPending || selectable.length === 0}
              title="Завести всех, кто попадает под текущий запрос"
            >
              Загрузить всех{query === '' ? ' из каталога' : ' по запросу'}
            </Button>
          )}
          <Button variant="ghost" onClick={close}>
            Закрыть
          </Button>
        </div>
      </div>
    </Drawer>
  )
}

interface CandidateRowProps {
  candidate: DirectoryCandidate
  checked: boolean
  onToggle: () => void
}

/**
 * Строка кандидата. Уже заведённые показываются, но недоступны для выбора:
 * скрывать их нельзя — оператор искал бы человека и не находил, не понимая,
 * что тот уже есть.
 */
function CandidateRow({ candidate, checked, onToggle }: CandidateRowProps) {
  const disabledInDirectory = candidate.status === 'disabled'
  return (
    <li>
      <label
        className={cn(
          'flex cursor-pointer items-center gap-2 rounded border border-line px-2 py-1.5 transition-colors',
          candidate.imported ? 'cursor-default opacity-60' : 'hover:border-accent/35 hover:bg-accent-soft/40',
        )}
      >
        <input
          type="checkbox"
          checked={checked}
          disabled={candidate.imported}
          onChange={onToggle}
          className="size-3.5 shrink-0 accent-[var(--accent)]"
        />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-xs text-fg">
            {candidate.display_name === '' ? candidate.subject : candidate.display_name}
          </span>
          <span className="block truncate font-mono text-[11px] text-muted">{candidate.subject}</span>
        </span>
        {candidate.imported && <span className="shrink-0 text-[11px] text-muted">уже добавлен</span>}
        {disabledInDirectory && !candidate.imported && (
          <span
            className="shrink-0 rounded border border-line px-1 text-[11px] text-muted"
            title="В каталоге выключен: доступ ему выдавать не следует"
          >
            выключен
          </span>
        )}
      </label>
    </li>
  )
}

/** Текст итога импорта: пропуски объясняются, а не прячутся. */
function importResultText(result: DirectoryImportResponse): string {
  const parts: string[] = []
  if (result.created.length > 0) {
    parts.push(`добавлено ${result.created.length} ${plural(result.created.length, PLURAL_PEOPLE)}`)
  }
  if (result.skipped_existing.length > 0) {
    parts.push(`уже были: ${result.skipped_existing.length}`)
  }
  if (result.skipped_missing.length > 0) {
    parts.push(`нет в каталоге: ${result.skipped_missing.length}`)
  }
  return parts.length === 0 ? 'Добавлять некого' : parts.join(', ')
}
