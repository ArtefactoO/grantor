import { cn } from './cn'

/**
 * Единая визуальная семантика выбранной интерактивной поверхности:
 * строка, пункт дерева, навигации или списка выбора. Геометрия остаётся
 * ответственностью компонента, а фон/контур/hover больше не расходятся.
 */
export function selectionSurfaceClassName(
  selected: boolean,
  className?: string,
): string {
  return cn(
    'ui-selection-surface',
    selected
      ? 'bg-selected text-text [box-shadow:inset_0_0_0_1px_var(--selection-outline)]'
      : 'hover:bg-panel2/60 hover:text-text',
    className,
  )
}

/** Единый active/idle-контракт для горизонтальной навигации по вкладкам. */
export function selectionTabClassName(
  selected: boolean,
  idleTone: 'muted' | 'faint' = 'muted',
  className?: string,
): string {
  return cn(
    'grantor-touch-target -mb-px border-b-2 transition-colors focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-accent',
    selected
      ? 'border-accent font-medium text-text'
      : cn(
          'border-transparent hover:text-text',
          idleTone === 'faint' ? 'text-faint' : 'text-muted',
        ),
    className,
  )
}
