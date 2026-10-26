// Форматирование времени для операторских таблиц: короткие русские
// относительные метки («5 мин назад») и полные timestamps для title.

/** «N мин назад» для ISO-строки; '—' для null/некорректных значений. */
export function formatRelative(iso: string | null | undefined): string {
  if (iso === null || iso === undefined || iso === '') {
    return '—'
  }
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) {
    return '—'
  }
  const diffSec = Math.floor((Date.now() - then) / 1000)
  if (diffSec < 60) {
    return 'только что'
  }
  const min = Math.floor(diffSec / 60)
  if (min < 60) {
    return `${min} мин назад`
  }
  const hours = Math.floor(min / 60)
  if (hours < 24) {
    return `${hours} ч назад`
  }
  const days = Math.floor(hours / 24)
  return `${days} дн назад`
}

/** Полная локальная дата-время для title/деталей; '—' для null. */
export function formatDateTime(iso: string | null | undefined): string {
  if (iso === null || iso === undefined || iso === '') {
    return '—'
  }
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) {
    return '—'
  }
  return date.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
