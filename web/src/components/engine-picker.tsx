import { EngineBadge } from './ui/badge'
import { Combobox } from '@project/ui'

export interface EnginePickerOption {
  value: string
  label: string
}

export interface EnginePickerProps {
  value: string
  options: readonly EnginePickerOption[]
  onValueChange: (value: string) => void
  label?: string
}

/** Searchable engine picker. Native option не используется: он не умеет
 * надёжно показывать брендовые SVG во всех браузерах. */
export function EnginePicker({
  value,
  options,
  onValueChange,
  label = 'Движок',
}: EnginePickerProps) {
  return (
    <Combobox
      value={value}
      label={label}
      searchLabel={`Поиск: ${label}`}
      searchPlaceholder="Название движка…"
      options={options.map((option) => ({
        ...option,
        icon: <EngineBadge engine={option.value} className="size-5" />,
        trigger: (
          <span className="flex min-w-0 items-center gap-2">
            <EngineBadge engine={option.value} className="size-5" />
            <span className="truncate">{option.label}</span>
          </span>
        ),
      }))}
      onValueChange={onValueChange}
    />
  )
}
