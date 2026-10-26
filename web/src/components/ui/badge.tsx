// Статусные чипы с точкой и бейджи движков — как в концепт-мокапе.
// Цветовая семантика фиксирована: ok/warn/danger/unmg; accent — только
// выбор/действие.
import type { ReactNode } from 'react'
import {
  Activity,
  Bot,
  Boxes,
  Database,
  Fish,
  Layers,
  Leaf,
  Rabbit,
  User,
  UserRound,
  Users,
  Waypoints,
} from '@project/ui/icons'
import type { LucideIcon } from '@project/ui/icons'
import { cn } from '@project/ui'
import { accountKindLabel, principalTypeLabel } from '../../lib/ui-copy'
import { principalTypeTone } from '../../lib/status'

export type ChipTone = 'ok' | 'warn' | 'danger' | 'unmg' | 'accent'

const TONE_CLASSES: Record<ChipTone, string> = {
  ok: 'bg-ok-soft text-ok',
  warn: 'bg-warn-soft text-warn',
  danger: 'bg-danger-soft text-danger',
  unmg: 'bg-unmg-soft text-unmg',
  accent: 'bg-accent-soft text-accent-text',
}

export interface StatusChipProps {
  tone: ChipTone
  children: ReactNode
  className?: string
  title?: string
}

/** Чип статуса: цветная точка + подпись на полупрозрачной подложке. */
export function StatusChip({ tone, children, className, title }: StatusChipProps) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex h-[22px] items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-xs font-medium',
        TONE_CLASSES[tone],
        className,
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {children}
    </span>
  )
}

const PRINCIPAL_TYPE_ICONS: Record<string, LucideIcon> = {
  human: UserRound,
  service: Bot,
  group: Users,
}

export interface PrincipalTypeIconProps {
  type: string
  className?: string
}

/** Единая иконка типа global principal: человек, service account или группа. */
export function PrincipalTypeIcon({ type, className }: PrincipalTypeIconProps) {
  const Icon = PRINCIPAL_TYPE_ICONS[type] ?? UserRound
  return (
    <Icon
      data-principal-type={type}
      className={cn('size-3.5 shrink-0', className)}
      aria-hidden="true"
    />
  )
}

export interface PrincipalTypeChipProps {
  type: string
  className?: string
}

/** Тип principal без статусной точки: семантику Human/Service несёт иконка. */
export function PrincipalTypeChip({ type, className }: PrincipalTypeChipProps) {
  const tone = principalTypeTone(type)
  return (
    <span
      title={principalTypeLabel(type)}
      className={cn(
        'inline-flex h-[22px] items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-xs font-medium',
        TONE_CLASSES[tone],
        className,
      )}
    >
      <PrincipalTypeIcon type={type} />
      {principalTypeLabel(type)}
    </span>
  )
}

// Иконка + брендовый цвет на движок; неизвестный движок — нейтральная
// иконка БД, а полное имя всегда в title/aria-label. Приоритет — SVG из
// web/src/assets/engines/<engine>.svg (кладутся руками, подхватываются
// сборкой автоматически, см. README там); нет файла — fallback на глиф
// lucide (self-contained, не бренд-логотип).

// Карта <engine> -> отдельный URL ассета; ?no-inline принципиален для CSS
// mask: Vite иначе превращает малые SVG в data URI, внутри которого символы
// разметки могут сделать итоговое значение mask-image невалидным в браузере.
const ENGINE_ICON_URLS: Record<string, string> = Object.fromEntries(
  Object.entries(
    import.meta.glob('../../assets/engines/*.svg', {
      eager: true,
      import: 'default',
      query: '?url&no-inline',
    }) as Record<string, string>,
  ).map(([path, url]) => [path.replace(/^.*\/([^/]+)\.svg$/, '$1'), url]),
)
interface EngineVisual {
  Icon: LucideIcon
  color: string
  label: string
}

const ENGINE_VISUALS: Record<string, EngineVisual> = {
  postgres: { Icon: Database, color: '#4f9ed6', label: 'PostgreSQL' },
  mongodb: { Icon: Leaf, color: '#4faa41', label: 'MongoDB' },
  mysql: { Icon: Fish, color: '#2b9fc4', label: 'MySQL' },
  rabbitmq: { Icon: Rabbit, color: '#ff7a33', label: 'RabbitMQ' },
  clickhouse: { Icon: Activity, color: '#e6c020', label: 'ClickHouse' },
  kafka: { Icon: Waypoints, color: '#9a86ea', label: 'Kafka' },
  redis: { Icon: Layers, color: '#e4574c', label: 'Redis' },
}

export interface EngineBadgeProps {
  engine: string
  className?: string
}

/** Бейдж движка: брендовая иконка в квадратной подложке; имя — в title.
 * Приоритет — SVG-ассет assets/engines/<engine>.svg, fallback — lucide. */
export function EngineBadge({ engine, className }: EngineBadgeProps) {
  const visual = ENGINE_VISUALS[engine]
  const Icon = visual?.Icon ?? Database
  const label = visual?.label ?? engine
  const assetURL = ENGINE_ICON_URLS[engine]
  const maskImage = assetURL === undefined ? undefined : `url("${assetURL}")`
  return (
    <span
      title={label}
      aria-label={label}
      className={cn(
        'inline-flex size-[22px] shrink-0 items-center justify-center rounded border border-line bg-panel2 text-muted',
        className,
      )}
    >
      {assetURL !== undefined ? (
        <span
          data-engine-brand={engine}
          className="size-3.5 bg-current"
          style={{
            WebkitMaskImage: maskImage,
            maskImage,
            WebkitMaskPosition: 'center',
            maskPosition: 'center',
            WebkitMaskRepeat: 'no-repeat',
            maskRepeat: 'no-repeat',
            WebkitMaskSize: 'contain',
            maskSize: 'contain',
          }}
          aria-hidden="true"
        />
      ) : (
        <Icon
          className="size-3.5"
          style={visual !== undefined ? { color: visual.color } : undefined}
          aria-hidden="true"
        />
      )}
    </span>
  )
}

// Иконка kind учётной записи: индивидуальная (login/service) — один
// человек, групповая (group/role) — множество; неизвестный kind движка
// получает нейтральную иконку и своё имя подписью (без engine-условий).
const ACCOUNT_KIND_ICONS: Record<string, LucideIcon> = {
  login: User,
  service: User,
  group: Users,
  role: Boxes,
}

export interface KindBadgeProps {
  kind: string
  principalType?: string | null
  className?: string
}

/** Бейдж kind аккаунта: иконка + подпись; группирующие kind визуально
 * отличаются от индивидуальных. Единый источник для таблицы и панелей. */
export function KindBadge({ kind, principalType, className }: KindBadgeProps) {
  const Icon = principalType === undefined || principalType === null
    ? (ACCOUNT_KIND_ICONS[kind] ?? Boxes)
    : (PRINCIPAL_TYPE_ICONS[principalType] ?? ACCOUNT_KIND_ICONS[kind] ?? Boxes)
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap text-muted',
        className,
      )}
      title={principalType === undefined || principalType === null
        ? kind
        : `${accountKindLabel(kind)} · ${principalTypeLabel(principalType)}`}
    >
      <Icon
        data-principal-type={principalType ?? undefined}
        className="size-3.5 shrink-0 text-faint"
        aria-hidden="true"
      />
      {accountKindLabel(kind)}
    </span>
  )
}

export interface TagBadgeProps {
  children: ReactNode
  className?: string
  title?: string
}

/** Нейтральный тег (environment и т.п.). */
export function TagBadge({ children, className, title }: TagBadgeProps) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex h-[22px] items-center whitespace-nowrap rounded border border-line bg-panel2 px-1.5 text-[11px] text-muted',
        className,
      )}
    >
      {children}
    </span>
  )
}
