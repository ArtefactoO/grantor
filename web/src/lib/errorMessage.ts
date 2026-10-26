// Единый способ достать человекочитаемый текст из значения ошибки: у
// Error (в т.ч. ApiError) — message, у остального — строковое
// представление. Убирает повтор тернарника
// `err instanceof Error ? err.message : String(err)` по экранам.

/** Текст ошибки: message у Error, иначе String(значение). */
export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
