// Осознанный выбор при ротации аккаунта, сидящего на общем пароле
// пользователя (ADR-0008: один пароль на пару пользователь+окружение).
//
// Ротация «на месте» такой аккаунт с общего пароля УВОДИТ: общий пароль
// остаётся прежним, остальные аккаунты пользователя продолжают жить на нём, а
// одноразовая выдача общего пароля отдаёт значение, для этого аккаунта уже
// мёртвое. Поэтому вместо тихого выполнения бэкенд отвечает 409 с кодом
// shared_credential_requires_choice и контекстом, а UI показывает выбор.
//
// Весь контекст (кого затронет, сколько их, нужен ли чекбокс подтверждения)
// приходит из этого 409: порог подтверждения — серверная настройка, и
// дублировать её во фронтенде значило бы иметь две расходящиеся версии
// правды.
import { useEffect, useState } from 'react'
import { ApiError } from '../lib/api'
import type { Account, SharedCredentialChoice } from '../lib/types'
import { SHARED_CREDENTIAL_CHOICE_CODE } from '../lib/types'
import { Dialog, Button, Spinner, ErrorBanner, RadioOptionCard } from '@project/ui'
import { pluralize, PLURAL_ACCOUNTS, PLURAL_SYSTEMS } from '../lib/plural'

/** Вариант выбора: сменить общий пароль или отвязать этот аккаунт. */
export type RotateChoice = 'shared' | 'detach'

/**
 * Достаёт контекст выбора из ошибки ротации: null, если это не 409
 * shared_credential_requires_choice (тогда ошибка показывается как обычно).
 * Проверяется именно код, а не текст: тексты меняются, коды — контракт.
 */
export function sharedCredentialChoice(err: unknown): SharedCredentialChoice | null {
  if (!(err instanceof ApiError) || err.code !== SHARED_CREDENTIAL_CHOICE_CODE) {
    return null
  }
  const body = err.body
  if (typeof body !== 'object' || body === null) {
    return null
  }
  const choice = (body as { shared_credential?: unknown }).shared_credential
  if (typeof choice !== 'object' || choice === null) {
    return null
  }
  const value = choice as SharedCredentialChoice
  return typeof value.principal_id === 'string' && Array.isArray(value.affected_connections)
    ? value
    : null
}

/** Перечисление подключений через запятую: длинный хвост схлопывается. */
function connectionList(choice: SharedCredentialChoice, maxVisible = 3): string {
  const names = choice.affected_connections.map((item) => item.display_name)
  if (names.length <= maxVisible) {
    return names.join(', ')
  }
  return `${names.slice(0, maxVisible).join(', ')} и ещё ${names.length - maxVisible}`
}

export interface RotateChoiceDialogProps {
  open: boolean
  account: Account
  choice: SharedCredentialChoice
  pending: boolean
  /** Текст ошибки последнего выполненного варианта (null — ошибок нет). */
  error: string | null
  onSubmit: (choice: RotateChoice, confirmed: boolean) => void
  onClose: () => void
}

export function RotateChoiceDialog({
  open,
  account,
  choice,
  pending,
  error,
  onSubmit,
  onClose,
}: RotateChoiceDialogProps) {
  // Ничего не предвыбрано: варианты не равнозначны (один меняет пароль во
  // всех системах пользователя, другой — только здесь), и «удобный» дефолт
  // здесь означал бы выбор за оператора.
  const [selected, setSelected] = useState<RotateChoice | null>(null)
  const [confirmed, setConfirmed] = useState(false)

  useEffect(() => {
    if (open) {
      setSelected(null)
      setConfirmed(false)
    }
  }, [open, account.id])

  // Чекбокс появляется только у варианта «общий пароль» и только когда
  // затронутых аккаунтов больше серверного порога.
  const needsConfirm = selected === 'shared' && choice.requires_confirm
  const canSubmit = selected !== null && (!needsConfirm || confirmed) && !pending

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Ротация пароля: ${account.engine_identity}`}
    >
      <div className="space-y-4">
        <div className="rounded-md border border-line bg-panel2/50 p-3 text-sm text-muted">
          Аккаунт использует общий пароль пользователя{' '}
          <span className="text-text">{choice.principal_display_name}</span> в окружении{' '}
          <span className="font-mono text-text">{choice.environment}</span>. Этот пароль
          общий для {pluralize(choice.affected_accounts, PLURAL_ACCOUNTS)}. Выберите, что сделать.
        </div>

        <div className="space-y-1.5">
          <RadioOptionCard
            name="rotate-choice"
            label="Ротировать общий пароль"
            hint={`Новый пароль получат все ${pluralize(choice.affected_accounts, PLURAL_ACCOUNTS)} пользователя: ${connectionList(choice)}.`}
            checked={selected === 'shared'}
            onSelect={() => {
              setSelected('shared')
              setConfirmed(false)
            }}
          />
          <RadioOptionCard
            name="rotate-choice"
            label="Отвязать и выдать собственный пароль"
            hint="Новый пароль получит только этот аккаунт. Общий пароль пользователя не изменится, остальные аккаунты продолжат работать."
            checked={selected === 'detach'}
            onSelect={() => {
              setSelected('detach')
              setConfirmed(false)
            }}
          />
        </div>

        {needsConfirm && (
          <div className="space-y-2 rounded-md border border-danger/40 bg-danger-soft p-3">
            <label className="flex cursor-pointer items-start gap-2 text-sm text-text">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 accent-danger"
              />
              Понимаю, что пароль сменится в {pluralize(choice.affected_accounts, PLURAL_SYSTEMS)}
            </label>
          </div>
        )}

        {error !== null && <ErrorBanner>{error}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose} disabled={pending}>
            Отмена
          </Button>
          <Button
            disabled={!canSubmit}
            onClick={() => {
              if (selected !== null) {
                onSubmit(selected, confirmed)
              }
            }}
          >
            {pending && <Spinner className="size-3.5 text-accent-ink" />}
            Ротировать
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
