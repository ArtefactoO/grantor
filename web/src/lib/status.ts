// Маппинг статусов бэкенда на семантические тона чипов. Перечисления —
// зеркала internal/core/{connections,operations,inventory}; неизвестные
// значения деградируют в серый (unmg), а не ломают рендер.

import type { ChipTone } from '../components/ui/badge'
import type { Drift } from './types'

/** Тон статуса connection (internal/core/connections.Status). */
export function connectionStatusTone(status: string): ChipTone {
  switch (status) {
    case 'active':
      return 'ok'
    case 'validating':
    case 'discovering':
    case 'credential_updating':
      return 'warn'
    case 'connection_failed':
    case 'discovery_failed':
    case 'degraded':
      return 'danger'
    case 'draft':
    case 'disabled':
    default:
      return 'unmg'
  }
}

/** Тон статуса операции (internal/core/operations.Status). */
export function operationStatusTone(status: string): ChipTone {
  switch (status) {
    case 'success':
      return 'ok'
    case 'pending_approval':
    case 'pending':
    case 'running':
      return 'warn'
    case 'failed':
    case 'partial':
      return 'danger'
    case 'cancelled':
    default:
      return 'unmg'
  }
}

/** Тон статуса binding (internal/core/inventory.BindingStatus). */
export function bindingStatusTone(status: string): ChipTone {
  switch (status) {
    case 'synced':
      return 'ok'
    case 'pending':
    case 'drift':
      return 'warn'
    case 'failed':
      return 'danger'
    // observed — не проблема и не ожидание: право просто не под управлением.
    case 'observed':
    default:
      return 'unmg'
  }
}

/**
 * Тон статуса account/resource/principal. account/principal: active —
 * зелёный, disabled/deleted — серый (жизнь записи закончена, это не
 * ошибка), provisioning — жёлтый (учётка ещё не подтверждена в целевой
 * системе), missing — красный (её там нет). resource
 * (internal/core/inventory): observed — зелёный (виден в целевой системе),
 * planned — серый (ещё не создан), missing — красный (пропал), stale —
 * жёлтый (давно не подтверждался). Неизвестные значения деградируют
 * в жёлтый.
 */
export function inventoryStatusTone(status: string): ChipTone {
  switch (status) {
    case 'active':
    case 'observed':
      return 'ok'
    case 'disabled':
    case 'deleted':
    case 'planned':
      return 'unmg'
    case 'missing':
      return 'danger'
    case 'provisioning':
    case 'stale':
      return 'warn'
    default:
      return 'warn'
  }
}

/** Тон ownership: managed — зелёный, unmanaged — серый. */
export function ownershipTone(ownership: string): ChipTone {
  return ownership === 'managed' ? 'ok' : 'unmg'
}

/**
 * Тон типа принципала. Тип — справочный признак, не тревога, поэтому
 * ok/warn/danger не используются: human подсвечен медью (выделение
 * человека, не действие), service и group — нейтральный серый.
 */
export function principalTypeTone(type: string): ChipTone {
  return type === 'human' ? 'accent' : 'unmg'
}

/**
 * Тон вида drift-finding (GET /api/v1/drift): деградация подключения и
 * расхождение managed binding — danger, внешние гранты и пропавшие
 * managed-ресурсы — warn; неизвестные виды деградируют в серый.
 */
export function driftKindTone(kind: string): ChipTone {
  switch (kind) {
    case 'connection_degraded':
    case 'binding_drift':
      return 'danger'
    case 'unmanaged_binding':
    case 'missing_resource':
    case 'missing_account':
      return 'warn'
    default:
      return 'unmg'
  }
}

/** Тон результата audit-события. */
export function auditResultTone(result: string): ChipTone {
  switch (result) {
    case 'success':
      return 'ok'
    case 'failure':
    case 'failed':
    case 'error':
      return 'danger'
    default:
      return 'unmg'
  }
}

/**
 * Настоящий drift подключения: расхождения MANAGED-состояния (drift_bindings
 * + missing_managed_resources + missing_managed_accounts). unmanaged_bindings
 * сюда не входят — это наблюдаемые discovery внешние гранты, а не
 * рассинхронизация того, чем управляет grantor (их количество показывает
 * карточка «Снимок кластера»).
 */
export function driftTotal(drift: Drift | undefined): number {
  if (drift === undefined) {
    return 0
  }
  return drift.drift_bindings + drift.missing_managed_resources + (drift.missing_managed_accounts ?? 0)
}

/** Статусы connection, при которых список поллится каждые 10 секунд. */
export function connectionInProgress(status: string): boolean {
  return status === 'discovering' || status === 'validating'
}

/** Статусы операции, при которых список поллится каждые 10 секунд. */
export function operationInProgress(status: string): boolean {
  return status === 'pending' || status === 'running' || status === 'pending_approval'
}

interface OperationStatusSource {
  status: string
  aggregate_status?: string
  kind?: string
  parent_id?: string | null
}

/** A durable database root may still have later stages after every current child is done. */
export function effectiveOperationStatus(op: OperationStatusSource): string {
  if ((op.kind === 'resource.create.database_with_roles' ||
    op.kind === 'postgres.resource.create.database_with_roles.v2') && op.parent_id === null) return op.status
  return op.aggregate_status || op.status
}

/**
 * true, пока bulk-операция не достигла терминального сводного статуса.
 * aggregate_status авторитетен (parent bulk остаётся running по дизайну);
 * при его отсутствии — fallback на собственный статус операции.
 */
export function bulkOperationInProgress(op: OperationStatusSource): boolean {
  return operationInProgress(effectiveOperationStatus(op))
}

/** Статусы connection, считающиеся stale/деградацией для стат-тайла. */
export function connectionIsStale(status: string): boolean {
  return (
    status === 'degraded' ||
    status === 'connection_failed' ||
    status === 'discovery_failed'
  )
}

/** Короткий id для моноширинных колонок таблиц. */
export function shortId(id: string | null | undefined): string {
  if (id === null || id === undefined || id === '') {
    return '—'
  }
  return id.slice(0, 8)
}
