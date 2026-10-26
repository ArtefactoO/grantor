// Правила pg_hba подключения (read-only).
//
// Доступ в PostgreSQL определяют три условия: сеть, правило pg_hba и SQL-права.
// Grantor управляет только третьим, поэтому выданная роль может не работать —
// самая частая причина «права выдали, а подключиться нельзя». Раздел показывает
// правила как есть и называет учётки, для которых подходящего правила не нашлось.
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert } from '@project/ui/icons'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { StatusChip } from '../components/ui/badge'
import { formatDateTime } from '../lib/time'
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableHeader,
  TableRow,
} from '@project/ui'

/** Одно правило pg_hba (ответ GET /connections/{id}/hba). */
export interface HBARule {
  number: number
  type: string
  databases: string[]
  users: string[]
  address: string
  netmask: string
  auth_method: string
  options: string[]
  error: string
}

export interface HBAResponse {
  supported: boolean
  customized: boolean
  truncated: boolean
  rules: HBARule[]
  uncovered_accounts: string[]
}

export function useConnectionHBA(connectionId: string) {
  return useQuery({
    queryKey: qk.connectionHBA(connectionId),
    queryFn: ({ signal }) =>
      api<HBAResponse>(`/api/v1/connections/${connectionId}/hba`, { signal }),
  })
}

export type ConnectionHBAQuery = Pick<ReturnType<typeof useConnectionHBA>, 'data' | 'isPending' | 'isError'>

export function accountHBARules(rules: HBARule[], identity: string, roles: Set<string>): HBARule[] {
  return rules.filter((rule) => rule.users.some((user) =>
    user === 'all' || user === identity ||
    (user.startsWith('+') && roles.has(user.slice(1))) ||
    user.startsWith('@') || user.startsWith('/'),
  )).sort((a, b) => a.number - b.number)
}

export function AccountHBASection({ query, identity, roles, observedAt }: {
  query?: ConnectionHBAQuery
  identity: string
  roles: Set<string>
  observedAt: string | null
}) {
  const rules = accountHBARules(query?.data?.rules ?? [], identity, roles)
  return (
    <details className="rounded-md border border-line bg-panel2/20">
      <summary className="grantor-touch-target cursor-pointer rounded-md px-3 py-2 text-sm font-medium text-text focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent">
        Правила pg_hba{query?.data?.supported ? ` · ${rules.length}` : ''}
      </summary>
      <div className="space-y-2 px-3 pb-3 text-xs text-muted">
        {query?.isPending ? <p role="status">Загружаются правила подключения…</p>
          : query?.isError ? <p role="alert">Не удалось загрузить HBA. Повторите загрузку страницы подключения.</p>
          : !query?.data?.supported ? <p>В текущем снимке нет данных HBA.</p>
          : <>
            <p>Правила по имени учётки, известным ролям и общие правила. Записи с файлами или регулярными выражениями требуют отдельной проверки.</p>
            <p>Снимок: {formatDateTime(observedAt)}. Соответствие файлу не подтверждает загрузку правил сервером или успешный вход. Учитывайте БД, TLS и адрес, который PostgreSQL видит после HAProxy или NAT.</p>
            {query.data.truncated && <p className="text-warn">Снимок HBA неполный. Часть правил может отсутствовать.</p>}
            {rules.length === 0 ? <p>Подходящих записей в снимке не найдено. Проверьте полный HBA подключения.</p> : (
              <ol className="max-h-72 space-y-2 overflow-y-auto" aria-label={`HBA для ${identity}`}>
                {rules.map((rule) => <li key={rule.number} className="space-y-1 border-t border-line pt-2 first:border-0 first:pt-0">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="tabular-nums text-faint">#{rule.number}</span>
                    <code className="text-text">{rule.type}</code>
                    <span className={rule.error !== '' || rule.auth_method === 'reject' ? 'text-danger' : 'text-muted'}>{rule.error !== '' ? 'Ошибка правила' : rule.auth_method}</span>
                  </div>
                  <div className="[overflow-wrap:anywhere]">БД: <code className="text-text">{rule.databases.join(', ')}</code></div>
                  <div className="[overflow-wrap:anywhere]">Источник: <code className="text-text">{rule.address === '' ? 'local' : `${rule.address}${rule.netmask === '' ? '' : `/${rule.netmask}`}`}</code></div>
                  <div className="[overflow-wrap:anywhere]">Пользователи: <code>{rule.users.join(', ')}</code></div>
                </li>)}
              </ol>
            )}
          </>}
      </div>
    </details>
  )
}

export function ConnectionHBASection({ data }: { data: HBAResponse }) {
  return (
    <section className="space-y-2">
      <div>
        <h2 className="text-sm font-semibold text-text">Правила pg_hba</h2>
        <p className="mt-0.5 text-xs text-muted">
          Доступ разрешают три условия: сеть, правило pg_hba и выданные права.
          Grantor управляет только правами. Правила показаны для справки и не
          изменяются.
        </p>
      </div>

      {!data.supported ? (
        <p className="rounded-md border border-line bg-panel2/40 px-3 py-2 text-sm text-muted">
          Правила недоступны: нужен PostgreSQL 15 или новее и право на
          представление <span className="font-mono text-text">pg_hba_file_rules</span>{' '}
          у учётной записи подключения.
        </p>
      ) : (
        <>
          {data.uncovered_accounts.length > 0 && (
            <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2">
              <p className="flex items-start gap-2 text-xs text-warn">
                <ShieldAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  Для этих учётных записей не нашлось подходящего правила. Вход
                  может быть невозможен даже с выданными правами:{' '}
                  <span className="font-mono">{data.uncovered_accounts.join(', ')}</span>
                </span>
              </p>
            </div>
          )}
          {data.truncated && (
            <p className="text-xs text-faint">
              Показаны первые {data.rules.length} правил; файл длиннее.
            </p>
          )}
          <TableContainer>
            <Table>
              <TableHeader>
                <tr>
                  <TableHead>№</TableHead>
                  <TableHead>Тип</TableHead>
                  <TableHead>Базы</TableHead>
                  <TableHead>Пользователи</TableHead>
                  <TableHead>Адрес</TableHead>
                  <TableHead>Метод</TableHead>
                </tr>
              </TableHeader>
              <TableBody>
                {data.rules.map((rule) => (
                  // Сломанная строка pg_hba сервером не применяется — это сам
                  // по себе сигнал, поэтому она подсвечена, а не скрыта.
                  <TableRow key={rule.number} className={rule.error !== '' ? 'text-danger' : undefined}>
                    <TableCell className="tabular-nums text-muted">{rule.number}</TableCell>
                    <TableCell className="font-mono text-[12px]">{rule.type}</TableCell>
                    <TableCell className="font-mono text-[12px]">{rule.databases.join(', ')}</TableCell>
                    <TableCell className="font-mono text-[12px]">{rule.users.join(', ')}</TableCell>
                    <TableCell className="font-mono text-[12px] text-muted">
                      {rule.address}{rule.netmask !== '' ? `/${rule.netmask}` : ''}
                    </TableCell>
                    <TableCell>
                      {rule.error !== '' ? (
                        <StatusChip tone="danger" title={rule.error}>Ошибка</StatusChip>
                      ) : (
                        <span className="font-mono text-[12px]">{rule.auth_method}</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
    </section>
  )
}
