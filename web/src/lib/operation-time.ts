export interface OperationTimeSearch {
  created_from?: string
  created_before?: string
}

export interface LocalDayRange {
  createdFrom: string
  createdBefore: string
  timeZone: string
}

export interface OperationsTodaySearch {
  connection?: string
  created_from: string
  created_before: string
}

export function validateOperationTimeSearch(
  search: Record<string, unknown>,
): OperationTimeSearch {
  return {
    ...(typeof search.created_from === 'string' && search.created_from.trim() !== ''
      ? { created_from: search.created_from.trim() }
      : {}),
    ...(typeof search.created_before === 'string' && search.created_before.trim() !== ''
      ? { created_before: search.created_before.trim() }
      : {}),
  }
}

/**
 * Границы текущего календарного дня браузера. Конструктор с локальными
 * компонентами учитывает фактический UTC offset и переход DST каждой границы.
 */
export function localDayRange(now = new Date()): LocalDayRange {
  const createdFrom = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const createdBefore = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1,
  )
  return {
    createdFrom: createdFrom.toISOString(),
    createdBefore: createdBefore.toISOString(),
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'local',
  }
}

export function operationsTodaySearch(
  range: LocalDayRange,
  connection?: string,
): OperationsTodaySearch {
  return {
    connection,
    created_from: range.createdFrom,
    created_before: range.createdBefore,
  }
}
