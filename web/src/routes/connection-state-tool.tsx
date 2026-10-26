// Connection-scoped «Состояние»: managed-only является применяемым manifest,
// любая расширенная комбинация секций — read-only snapshot последнего discovery.
import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, FileCode2, ShieldAlert, Upload } from '@project/ui/icons'
import { apiPostRaw } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  AccessExportSection,
  Connection,
  ManifestApplyResponse,
  ManifestPlanAction,
  ManifestPlanResponse,
} from '../lib/types'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  Button,
  StatTile,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  Spinner,
  EmptyState,
  ErrorBanner,
  TableCopyableValue,
} from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import type { ChipTone } from '../components/ui/badge'
import { CheckboxChipGroup } from '../components/ui/selection-chips'
import { BulkOperationPanel } from '../components/BulkOperationPanel'
import { ElevatedAccessDot } from '../components/ui/access-chips'
import { UI_COPY } from '../lib/ui-copy'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'
import {
  STATE_SECTIONS,
  detectStateDocument,
  detectStateDocumentFormat,
  isManagedManifest,
  stateExportPath,
} from './connection-state'
import type {
  AccessDocumentKind,
  StateDocumentFormat,
} from './connection-state'

const CONTENT_TYPES: Record<StateDocumentFormat, string> = {
  json: 'application/json',
  yaml: 'application/yaml',
}

const SECTION_LABELS: Record<AccessExportSection, string> = {
  managed: UI_COPY.managed,
  unmanaged: UI_COPY.unmanaged,
  roles: UI_COPY.roles,
  accounts: UI_COPY.accounts,
}

const SECTION_OPTIONS = STATE_SECTIONS.map((section) => ({
  value: section,
  label: SECTION_LABELS[section],
}))

async function fetchDocument(path: string, signal?: AbortSignal): Promise<string> {
  const response = await fetch(path, { credentials: 'same-origin', signal })
  if (response.status === 401) {
    window.location.href = '/auth/login'
    throw new Error('unauthorized')
  }
  const text = await response.text()
  if (!response.ok) {
    let message = `HTTP ${response.status}`
    try {
      const payload = JSON.parse(text) as { error?: unknown }
      if (typeof payload.error === 'string') message = payload.error
    } catch {
      // Не-JSON ошибка остаётся HTTP-статусом, сырой ответ не отражается.
    }
    throw new Error(message)
  }
  return text
}

function downloadDocument(
  text: string,
  fileName: string,
  format: StateDocumentFormat,
): void {
  const type = format === 'json' ? 'application/json' : 'application/yaml'
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

type DocumentSource = 'server' | 'local'

export function ConnectionStateTool({ connection }: { connection: Connection }) {
  const auth = useAuth()
  const canPlan = roleAtLeast(auth.role, 'operator')
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const queryClient = useQueryClient()
  const connectionId = connection.id
  const [sections, setSections] = useState<Set<AccessExportSection>>(
    () => new Set(['managed']),
  )
  const [text, setText] = useState('')
  const [format, setFormat] = useState<StateDocumentFormat>('yaml')
  const [fileName, setFileName] = useState<string | null>(null)
  const [documentKind, setDocumentKind] = useState<AccessDocumentKind>('manifest')
  const [documentSource, setDocumentSource] = useState<DocumentSource>('server')
  const [documentConnectionId, setDocumentConnectionId] = useState('')
  const [documentPending, setDocumentPending] = useState(false)
  const [documentError, setDocumentError] = useState<string | null>(null)
  const [snapshotUploadNotice, setSnapshotUploadNotice] = useState(false)
  const [planResult, setPlanResult] = useState<ManifestPlanResponse | null>(null)
  const [plannedText, setPlannedText] = useState<string | null>(null)
  const [planError, setPlanError] = useState<string | null>(null)
  const [applyError, setApplyError] = useState<string | null>(null)
  const [elevatedConfirmed, setElevatedConfirmed] = useState(false)
  const [operationId, setOperationId] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const requestedDocumentRef = useRef('')
  const sectionsKey = STATE_SECTIONS.filter((section) => sections.has(section)).join(',')
  const manifestMode = isManagedManifest(sections) && documentKind === 'manifest'

  const clearPlan = () => {
    setPlanResult(null)
    setPlannedText(null)
    setPlanError(null)
    setApplyError(null)
    setElevatedConfirmed(false)
    setOperationId(null)
  }

  useEffect(() => {
    if (
      sections.size === 0 ||
      (documentSource === 'local' && documentConnectionId === connectionId)
    ) return
    const requestKey = `${connectionId}:${sectionsKey}`
    if (requestedDocumentRef.current === requestKey) return
    requestedDocumentRef.current = requestKey
    const controller = new AbortController()
    setDocumentPending(true)
    setDocumentError(null)
    setText('')
    setFormat('yaml')
    setFileName(null)
    clearPlan()
    void fetchDocument(stateExportPath(connectionId, sections, 'yaml'), controller.signal)
      .then((body) => {
        if (controller.signal.aborted) return
        setText(body)
        setDocumentKind(isManagedManifest(sections) ? 'manifest' : 'snapshot')
        setDocumentConnectionId(connectionId)
        setDocumentSource('server')
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return
        if (requestedDocumentRef.current === requestKey) requestedDocumentRef.current = ''
        setText('')
        setDocumentError(errorMessage(error))
      })
      .finally(() => {
        if (!controller.signal.aborted) setDocumentPending(false)
      })
    return () => controller.abort()
  }, [connectionId, sectionsKey, documentSource]) // eslint-disable-line react-hooks/exhaustive-deps

  const planMutation = useMutation({
    mutationFn: (body: string) =>
      apiPostRaw<ManifestPlanResponse>(
        `/api/v1/access/plan?connection=${encodeURIComponent(connectionId)}`,
        body,
        CONTENT_TYPES[format],
      ),
    onSuccess: (data, body) => {
      setPlanError(null)
      setPlanResult(data)
      setPlannedText(body)
      setElevatedConfirmed(false)
    },
    onError: (error: unknown) => {
      setPlanError(errorMessage(error))
      setPlanResult(null)
      setPlannedText(null)
    },
  })

  const applyMutation = useMutation({
    mutationFn: (body: string) =>
      apiPostRaw<ManifestApplyResponse>(
        `/api/v1/access/apply?connection=${encodeURIComponent(connectionId)}${elevatedConfirmed ? '&confirm=true' : ''}`,
        body,
        CONTENT_TYPES[format],
      ),
    onSuccess: (data) => {
      setApplyError(null)
      setOperationId(data.operation_id)
      setPlanResult(null)
      setPlannedText(null)
      setElevatedConfirmed(false)
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
    onError: (error: unknown) => setApplyError(errorMessage(error)),
  })

  const actions = planResult?.plan.actions ?? []
  const unresolved = planResult?.plan.unresolved ?? []
  const summary = planResult?.summary ?? null
  const creates = actions.filter((action) => action.kind === 'create_account')
  const grants = actions.filter((action) => action.kind === 'grant')
  const revokes = actions.filter((action) => action.kind === 'revoke')
  const others = actions.filter(
    (action) => !['create_account', 'grant', 'revoke'].includes(action.kind),
  )
  const planStale = plannedText !== null && plannedText !== text
  const hasElevated = summary !== null && summary.dangerous > 0
	const postgresCreationBlocked = creates.length > 0 && postgresProvisioningIssue(connection) !== null
  const canApply =
    planResult !== null &&
    !planStale &&
    actions.length > 0 &&
    !applyMutation.isPending &&
		!postgresCreationBlocked &&
    (!hasElevated || (isAdmin && elevatedConfirmed))

  const chooseSections = (next: Set<AccessExportSection>) => {
    if (
      next.size === sections.size &&
      STATE_SECTIONS.every((section) => next.has(section) === sections.has(section))
    ) return
    setDocumentSource('server')
    setSnapshotUploadNotice(false)
    setSections(next)
    if (next.size === 0) {
      requestedDocumentRef.current = ''
      clearPlan()
      setText('')
      setFileName(null)
      setDocumentKind('snapshot')
      setDocumentPending(false)
      setDocumentError(null)
    }
  }

  const pickFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (file === undefined) return
    void file.text().then((content) => {
      const detected = detectStateDocument(content, file.name)
      if (detected === null) {
        setDocumentError('Не удалось определить документ: ожидается access manifest или access_snapshot')
        return
      }
      clearPlan()
      setDocumentError(null)
      // Молчаливое переключение в read-only оставляло пользователя без
      // ответа, куда делись plan и apply.
      setSnapshotUploadNotice(detected.kind === 'snapshot')
      setDocumentSource('local')
      setDocumentConnectionId(connectionId)
      setSections(detected.sections)
      setDocumentKind(detected.kind)
      setFormat(detectStateDocumentFormat(content, file.name))
      setFileName(file.name)
      setText(content)
    })
  }

  const extractManaged = () => {
    requestedDocumentRef.current = ''
    setSnapshotUploadNotice(false)
    setDocumentSource('server')
    setSections(new Set(['managed']))
  }

  return (
    <div className="space-y-4 pb-12">
      <section className="overflow-hidden rounded-[10px] border border-line bg-panel shadow-[var(--highlight-inset)]">
        <div className="flex min-h-11 flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <FileCode2 className="size-4 text-muted" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-medium">Состояние подключения</h2>
            <p className="text-xs text-muted">Манифест и фактический снимок в одном инструменте</p>
          </div>
        </div>

        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line px-3 py-3">
          <div>
            <div className="text-xs text-muted">Что включить в документ</div>
            <CheckboxChipGroup
              label="Секции документа"
              options={SECTION_OPTIONS}
              selected={sections}
              onChange={(next) => chooseSections(new Set(next))}
              className="mt-1.5"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.yaml,.yml,application/json,application/yaml"
              onChange={pickFile}
              className="hidden"
              aria-label="Файл состояния"
            />
            <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
              <Upload className="size-3.5" aria-hidden="true" />
              Загрузить
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={text === '' || documentPending}
              onClick={() => downloadDocument(
                text,
                fileName ?? (manifestMode ? `access-manifest.${format}` : `access-snapshot.${format}`),
                format,
              )}
            >
              <Download className="size-3.5" aria-hidden="true" />
              Скачать {format.toUpperCase()}
            </Button>
          </div>
        </div>

        {sections.size === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={FileCode2}
              title="Секции не выбраны"
              description="Выберите одну или несколько секций, чтобы сформировать документ состояния подключения."
            />
          </div>
        ) : (
          <>
            {documentError !== null && (
              <div className="px-4 pt-4"><ErrorBanner>{documentError}</ErrorBanner></div>
            )}
            {snapshotUploadNotice && (
              <div
                role="status"
                aria-label="Загружен аудит-снимок"
                className="mx-4 mt-4 flex flex-wrap items-center gap-3 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-text"
              >
                <p className="min-w-0 flex-1">
                  Загружен <code>access_snapshot</code>, аудит-документ: plan и apply
                  для него недоступны. Изменения применяются через managed-манифест.
                </p>
                <Button variant="outline" size="sm" onClick={extractManaged}>
                  Извлечь управляемое состояние
                </Button>
              </div>
            )}
            <div className="grid min-h-[430px] lg:grid-cols-[minmax(0,1.3fr)_minmax(280px,.7fr)]">
              <section className="min-w-0 border-b border-line p-4 lg:border-b-0 lg:border-r">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-muted">
                    {fileName ?? (manifestMode ? `access-manifest.${format}` : `access-snapshot.${format}`)}
                  </span>
                  <span
                    title={manifestMode ? undefined : 'Снапшот служит аудит-документом: plan и apply работают только с managed-манифестом'}
                  >
                    <StatusChip tone={manifestMode ? 'accent' : 'unmg'}>
                      {manifestMode ? 'Manifest' : 'Read-only snapshot'}
                    </StatusChip>
                  </span>
                  {documentPending && <Spinner className="size-3.5" />}
                </div>
                <Textarea
                  value={text}
                  onChange={(event) => {
                    setText(event.target.value)
                    setFileName(null)
                    setDocumentSource('local')
                  }}
                  readOnly={!manifestMode || !canPlan}
                  rows={18}
                  spellCheck={false}
                  aria-label={manifestMode ? 'Текст манифеста' : 'Текст аудит-снимка'}
                  className="min-h-[365px] resize-y font-mono text-[12px]"
                  placeholder={documentPending ? 'Загрузка состояния…' : undefined}
                />
              </section>

              <aside className="p-4">
                {manifestMode ? (
                  <ManifestPlanPanel
                    canPlan={canPlan}
                    text={text}
                    planPending={planMutation.isPending}
                    planError={planError}
                    applyError={applyError}
                    planResult={planResult}
                    planStale={planStale}
                    elevatedConfirmed={elevatedConfirmed}
                    isAdmin={isAdmin}
                    canApply={canApply}
                    applyPending={applyMutation.isPending}
                    provisioningBlocked={postgresCreationBlocked}
                    connection={connection}
                    onPlan={() => {
                      setApplyError(null)
                      setOperationId(null)
                      planMutation.mutate(text)
                    }}
                    onApply={() => {
                      if (plannedText !== null) applyMutation.mutate(plannedText)
                    }}
                    onElevatedConfirmed={setElevatedConfirmed}
                  />
                ) : (
                  <SnapshotPanel
                    sections={sections}
                    uploaded={documentSource === 'local'}
                    onExtractManaged={extractManaged}
                  />
                )}
              </aside>
            </div>
          </>
        )}
      </section>

      {operationId !== null && (
        <BulkOperationPanel operationId={operationId} accounts={[]} onClose={() => setOperationId(null)} />
      )}

      {manifestMode && planResult !== null && summary !== null && (
        <div className="space-y-4">
          <PlanGroup title="Отозвать роли" tone="danger" actions={revokes} prominent />
          <PlanGroup title="Создать аккаунты" tone="accent" actions={creates} />
          <PlanGroup title="Выдать роли" tone="ok" actions={grants} />
          <PlanGroup title="Прочие действия" tone="unmg" actions={others} />
          {unresolved.length > 0 && <UnresolvedTable entries={unresolved} />}
        </div>
      )}
    </div>
  )
}

function SnapshotPanel({
  sections,
  uploaded,
  onExtractManaged,
}: {
  sections: ReadonlySet<AccessExportSection>
  uploaded: boolean
  onExtractManaged: () => void
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-text">Аудит-снимок</h3>
        <p className="mt-1 text-sm text-muted">
          Документ показывает выбранные секции состояния и не применяется к кластеру.
        </p>
      </div>
      <div className="rounded-md border border-line bg-panel2 px-3 py-2 text-sm text-muted">
        Read-only: plan и apply недоступны для <code>access_snapshot</code>.
        Снимок содержит unmanaged и scoped-права, которые managed-манифест не
        выражает, поэтому конвертация была бы с потерями. Для изменений
        извлеките управляемое состояние.
      </div>
      <dl className="grid grid-cols-2 gap-2">
        {STATE_SECTIONS.map((section) => (
          <div key={section} className="rounded-md border border-line px-3 py-2">
            <dt className="text-xs text-muted">{SECTION_LABELS[section]}</dt>
            <dd className="mt-1 text-sm font-medium text-text">
              {sections.has(section) ? 'Included' : '—'}
            </dd>
          </div>
        ))}
      </dl>
      {uploaded && (
        <p className="text-xs text-faint">
          Извлечение загрузит свежий Managed export выбранного подключения с сервера.
          Непредставимые scoped и непривязанные grants не конвертируются в браузере.
        </p>
      )}
      <Button onClick={onExtractManaged}>Извлечь управляемое состояние</Button>
    </div>
  )
}

interface ManifestPlanPanelProps {
  canPlan: boolean
  text: string
  planPending: boolean
  planError: string | null
  applyError: string | null
  planResult: ManifestPlanResponse | null
  planStale: boolean
  elevatedConfirmed: boolean
  isAdmin: boolean
  canApply: boolean
  applyPending: boolean
  provisioningBlocked: boolean
  connection: Connection
  onPlan: () => void
  onApply: () => void
  onElevatedConfirmed: (value: boolean) => void
}

function ManifestPlanPanel(props: ManifestPlanPanelProps) {
  const summary = props.planResult?.summary
  const actions = props.planResult?.plan.actions ?? []
  const unresolved = props.planResult?.plan.unresolved ?? []
  const hasElevated = (summary?.dangerous ?? 0) > 0
  const provisioningBlockerId = `postgres-manifest-${props.connection.id}-blocker`
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-text">Dry-run перед применением</h3>
        <p className="mt-1 text-sm text-muted">
          Загруженный или отредактированный Managed-документ сначала проходит plan.
        </p>
      </div>
      {!props.canPlan && (
        <div className="rounded-md border border-line bg-panel2 px-3 py-2 text-sm text-muted">
          Просмотр и скачивание доступны; plan и apply требуют роли operator.
        </div>
      )}
      {props.planError !== null && <ErrorBanner>Plan: {props.planError}</ErrorBanner>}
      {props.applyError !== null && <ErrorBanner>Apply: {props.applyError}</ErrorBanner>}
      {props.planStale && (
        <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
          Документ изменён после plan. Постройте его заново.
        </div>
      )}
      {props.provisioningBlocked && <PostgresProvisioningNotice connection={props.connection} id={provisioningBlockerId} />}
      <div className="grid grid-cols-2 gap-2">
        <StatTile label="Создать" value={summary?.creates ?? 0} tone="accent" />
        <StatTile label="Выдать" value={summary?.grants ?? 0} tone="ok" />
        <StatTile label="Отозвать" value={summary?.revokes ?? 0} tone="danger" />
        <StatTile label="Ошибки" value={unresolved.length} tone="warn" />
      </div>
      {props.planResult !== null && actions.length === 0 && unresolved.length === 0 && (
        <div className="rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm text-ok">
          Изменений нет: текущее Managed-состояние уже соответствует манифесту.
        </div>
      )}
      {hasElevated && (
        <div className="space-y-2 rounded-md border border-danger/40 bg-danger-soft px-3 py-2.5">
          <div className="flex items-center gap-2 text-sm text-danger">
            <ShieldAlert className="size-4" aria-hidden="true" />
            План затрагивает роли с широкими полномочиями
          </div>
          <label className="flex items-start gap-2 text-xs text-text">
            <input
              type="checkbox"
              checked={props.elevatedConfirmed}
              disabled={!props.isAdmin}
              onChange={(event) => props.onElevatedConfirmed(event.target.checked)}
              className="mt-0.5 accent-danger"
            />
            Я понимаю последствия и подтверждаю применение
          </label>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          disabled={!props.canPlan || props.text.trim() === '' || props.planPending}
          onClick={props.onPlan}
        >
          {props.planPending && <Spinner className="size-3.5 text-accent-ink" />}
          Построить план
        </Button>
        <Button
          variant={(summary?.revokes ?? 0) > 0 ? 'danger' : 'outline'}
          aria-describedby={props.provisioningBlocked ? provisioningBlockerId : undefined}
          disabled={!props.canApply}
          onClick={props.onApply}
        >
          {props.applyPending && <Spinner className="size-3.5" />}
          Применить
        </Button>
      </div>
    </div>
  )
}

function PlanGroup({
  title,
  tone,
  actions,
  prominent = false,
}: {
  title: string
  tone: ChipTone
  actions: ManifestPlanAction[]
  prominent?: boolean
}) {
  if (actions.length === 0) return null
  return (
    <div className={prominent ? 'space-y-2 rounded-lg border border-danger/40 p-3' : 'space-y-2'}>
      <div className="flex items-center gap-2">
        <StatusChip tone={tone}>{title}</StatusChip>
        <span className="text-sm tabular-nums text-muted">{actions.length}</span>
      </div>
      <TableContainer>
        <Table>
          <TableHeader>
            <tr>
              <TableHead>Принципал</TableHead>
              <TableHead>Подключение</TableHead>
              <TableHead>Роль</TableHead>
              <TableHead>Identity</TableHead>
              <TableHead>Причина</TableHead>
            </tr>
          </TableHeader>
          <TableBody>
            {actions.map((action, index) => (
              <TableRow key={`${action.kind}-${action.principal}-${action.connection}-${action.role}-${index}`}>
                <TableCell className="font-mono text-[13px]">
                  <TableCopyableValue
                    value={action.principal}
                    label={`Копировать имя принципала ${action.principal}`}
                  />
                </TableCell>
                <TableCell className="text-muted">{action.connection}</TableCell>
                <TableCell>
                  <span className="inline-flex items-center gap-1.5">
                    {action.dangerous && <ElevatedAccessDot />}
                    <span className="font-mono text-[13px]">{action.role}</span>
                  </span>
                </TableCell>
                <TableCell className="font-mono text-[12px] text-muted">{action.account_engine_identity ?? '—'}</TableCell>
                <TableCell className="text-muted">{action.reason ?? '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}

function UnresolvedTable({ entries }: { entries: ManifestPlanResponse['plan']['unresolved'] }) {
  return (
    <div className="space-y-2">
      <StatusChip tone="warn">Unresolved {entries.length}</StatusChip>
      <TableContainer>
        <Table>
          <TableHeader>
            <tr>
              <TableHead>Принципал</TableHead>
              <TableHead>Подключение</TableHead>
              <TableHead>Роль</TableHead>
              <TableHead>Причина</TableHead>
            </tr>
          </TableHeader>
          <TableBody>
            {entries.map((entry, index) => (
              <TableRow key={`${entry.principal}-${entry.connection}-${entry.role}-${index}`}>
                <TableCell className="font-mono text-[13px]">
                  <TableCopyableValue
                    value={entry.principal}
                    label={`Копировать имя принципала ${entry.principal}`}
                  />
                </TableCell>
                <TableCell className="text-muted">{entry.connection}</TableCell>
                <TableCell className="font-mono text-[13px]">{entry.role}</TableCell>
                <TableCell className="text-warn">{entry.reason}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
