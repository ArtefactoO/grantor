// Компактный показ одного права — единый для всех таблиц, карточек аккаунтов,
// ролей и ресурсов.
//
// Право показывается короткой подписью, собранной на backend, но полное
// исходное выражение остаётся доступным всегда: в tooltip, в панели
// подробностей и через кнопку копирования. Это и есть критерий готовности —
// любое обнаруженное право можно прочитать и скопировать целиком, независимо
// от движка и длины выражения.
//
// Подпись занимает не более двух строк: список прав аккаунта бывает длинным,
// и одна разросшаяся строка ломает ритм таблицы. Обрезка — по границе строки
// средствами CSS (line-clamp), а не обрезанием строки в JS: так не теряются
// отдельные символы и не появляется «…» посреди идентификатора.
import type { KeyboardEvent } from 'react'
import { cn, CopyButton, Tooltip } from '@project/ui'
import type { PermissionEntry } from '../../lib/permission-view'

/** Тихий маркер права с широкими полномочиями. */
export function DangerousPermissionDot({ title }: { title?: string }) {
  return (
    <span
      className="mt-1 size-1.5 shrink-0 rounded-full bg-danger"
      aria-label="Опасное право"
      title={title ?? 'Право предоставляет широкие полномочия'}
    />
  )
}

export interface PermissionChipProps {
  entry: PermissionEntry
  /** Открыть панель подробностей. Без обработчика право не кликабельно. */
  onOpen?: (entry: PermissionEntry) => void
  /** Показывать кнопку копирования при наведении и фокусе. */
  copyable?: boolean
  className?: string
}

/**
 * Одно право в компактном виде: подпись, точка опасности, кнопка копирования.
 * Кликабельность выражена явно — это кнопка, а не div с обработчиком, поэтому
 * она доступна с клавиатуры и объявляется screen reader без дополнительной
 * разметки.
 */
export function PermissionChip({
  entry,
  onOpen,
  copyable = true,
  className,
}: PermissionChipProps) {
  const interactive = onOpen !== undefined

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    // Radix-подобные поверхности реагируют на Enter и Space одинаково;
    // кнопка делает это сама, обработчик нужен только чтобы Space не
    // прокручивал страницу внутри длинного списка.
    if (event.key === ' ') {
      event.preventDefault()
      onOpen?.(entry)
    }
  }

  const label = (
    <span className="flex min-w-0 items-start gap-1.5">
      {entry.dangerous && <DangerousPermissionDot title={entry.view.danger_reason} />}
      <span className="line-clamp-2 min-w-0 break-all text-left font-mono text-[11px] leading-[1.35]">
        {entry.label}
      </span>
    </span>
  )

  return (
    <span
      className={cn(
        'group/permission inline-flex min-w-0 max-w-full items-start gap-1',
        className,
      )}
    >
      <Tooltip content={<span className="font-mono text-[11px]">{entry.raw}</span>}>
        {interactive ? (
          <button
            type="button"
            onClick={() => onOpen?.(entry)}
            onKeyDown={handleKeyDown}
            aria-label={`Подробности права ${entry.raw}`}
            className={cn(
              'grantor-touch-target ui-control-feedback ui-metadata-chip min-w-0 max-w-full cursor-pointer rounded border border-line bg-panel2 px-1.5 py-0.5',
              'text-muted hover:border-accent/35 hover:bg-accent-soft/55 hover:text-accent',
              'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
            )}
          >
            {label}
          </button>
        ) : (
          <span className="min-w-0 max-w-full rounded border border-line bg-panel2 px-1.5 py-0.5 text-muted">
            {label}
          </span>
        )}
      </Tooltip>
      {copyable && (
        <CopyButton
          value={entry.raw}
          compact
          label="Скопировать право"
          // Кнопка не занимает место в потоке до наведения: в плотном списке
          // постоянно видимые иконки перегружают строку.
          className="[@media(hover:hover)]:opacity-0 [@media(hover:hover)]:group-hover/permission:opacity-100 [@media(hover:hover)]:group-focus-within/permission:opacity-100"
        />
      )}
    </span>
  )
}
