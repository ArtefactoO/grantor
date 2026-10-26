// Индексирует список сущностей с полем id в Map для O(1) доступа по
// идентификатору. Убирает повтор `useMemo(new Map + for set)` по экранам
// (маппинги permission/connection/principal/account по id).

/** Собирает Map<id, item> из списка сущностей со строковым id. */
export function indexById<T extends { id: string }>(items: readonly T[]): Map<string, T> {
  const map = new Map<string, T>()
  for (const item of items) {
    map.set(item.id, item)
  }
  return map
}
