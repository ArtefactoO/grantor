// Интервалы фонового поллинга react-query (мс) — единый источник для
// refetchInterval экранов, чтобы не разбрасывать «магические» числа.

/** Панель запущенной bulk-операции: частый поллинг до терминала. */
export const POLL_OPERATION_MS = 3_000

/** Экран «Операции»: авто-обновление, пока в выборке есть незавершённые
 * (pending/pending_approval/running); без них поллинг выключен. */
export const POLL_OPERATIONS_MS = 5_000

/** Списки с незавершёнными операциями/discovery. */
export const POLL_LIST_MS = 10_000

/** Очередь подтверждений: новые операции появляются в фоне. */
export const POLL_APPROVALS_MS = 15_000

/** Сводные дашборды (обзор, дрифт): лёгкий поллинг. */
export const POLL_OVERVIEW_MS = 30_000
