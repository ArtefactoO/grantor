// Хелпер поверх fetch для API grantor: JSON, same-origin cookie-сессия,
// CSRF-заголовок на мутирующих запросах, обработка {"error":"..."} и
// редирект на OIDC-логин при 401.

/** Ошибка API с HTTP-статусом и текстом из {"error": "..."}. */
export class ApiError extends Error {
  readonly status: number

  /**
   * Машиночитаемый код из {"code": "..."} — есть только у ошибок, на которые
   * UI обязан реагировать поведением, а не показом текста (например 409
   * shared_credential_requires_choice). null, если бэкенд кода не прислал.
   */
  readonly code: string | null

  /**
   * Разобранное тело ошибки целиком: рядом с кодом бэкенд присылает контекст
   * решения (затронутые подключения, порог подтверждения). Тип неизвестен —
   * разбирает вызывающий, который знает свой код.
   */
  readonly body: unknown

  /** Delay requested by the server; callers decide whether retry is safe. */
  readonly retryAfterMs: number | null

  constructor(status: number, message: string, code: string | null = null, body: unknown = null, retryAfterMs: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
    this.retryAfterMs = retryAfterMs
  }
}

function retryAfterDelay(value: string | null): number | null {
  if (value === null || value.trim() === '') return null
  const raw = value.trim()
  if (/^\d+$/.test(raw)) {
    const delay = Number(raw) * 1000
    return Number.isFinite(delay) ? delay : null
  }
  // HTTP-date, not a negative/fractional number accepted by Date.parse.
  if (!/^[A-Za-z]/.test(raw)) return null
  const timestamp = Date.parse(raw)
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - Date.now()) : null
}

/** Машиночитаемый код ошибки API, если он есть у этого значения. */
export function apiErrorCode(err: unknown): string | null {
  return err instanceof ApiError ? err.code : null
}

// CSRF token и имя заголовка приходят из GET /auth/me и выставляются
// AuthProvider'ом до первого мутирующего запроса. Имя заголовка берётся с
// бэкенда (auth.CSRFHeader), а не хардкодится — иначе расхождение Go↔web
// молча ломало бы все мутации (аудит A3). Fallback — историческое имя.
const defaultCSRFHeader = 'X-Grantor-CSRF'
let csrfToken = ''
let csrfHeader = defaultCSRFHeader

/** Запоминает CSRF token и имя заголовка сессии для мутирующих запросов. */
export function setCsrf(token: string, header?: string): void {
  csrfToken = token
  csrfHeader = header && header !== '' ? header : defaultCSRFHeader
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export interface ApiOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  /**
   * Сырое тело запроса как есть (манифест доступов в JSON или YAML) с явным
   * contentType. Взаимоисключимо с body: rawBody не сериализуется.
   */
  rawBody?: string
  contentType?: string
  signal?: AbortSignal
}

/** Машиночитаемый код из тела ошибки, если бэкенд его прислал. */
function errorCode(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) {
    return null
  }
  const code = (value as { code?: unknown }).code
  return typeof code === 'string' && code !== '' ? code : null
}

function isErrorPayload(value: unknown): value is { error: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  )
}

/**
 * Скачивает ответ по path как файл filename: тянет тело same-origin,
 * при не-ok разбирает {"error":"..."} (как api()) и бросает Error с этим
 * текстом, иначе создаёт временный object URL и кликает по скрытой ссылке.
 * Используется экспортом манифеста доступов (JSON/YAML).
 */
export async function downloadBlob(path: string, filename: string): Promise<void> {
  const response = await fetch(path, { credentials: 'same-origin' })
  if (!response.ok) {
    let message = `HTTP ${response.status}`
    try {
      const data: unknown = await response.json()
      if (isErrorPayload(data)) {
        message = data.error
      }
    } catch {
      // Тело не JSON — оставляем HTTP-статус.
    }
    throw new Error(message)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

/** Выполняет запрос к API и возвращает распарсенный JSON-ответ. */
export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.rawBody !== undefined) {
    headers['Content-Type'] = options.contentType ?? 'application/json'
  } else if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (MUTATING_METHODS.has(method) && csrfToken !== '') {
    headers[csrfHeader] = csrfToken
  }

  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body:
        options.rawBody ??
        (options.body !== undefined ? JSON.stringify(options.body) : null),
      signal: options.signal ?? null,
    })
  } catch (err: unknown) {
    // AbortError пробрасываем как есть — react-query отменяет запросы сам.
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw err
    }
    throw new ApiError(0, 'сеть недоступна или API не отвечает')
  }

  if (response.status === 401) {
    // Сессии нет или она истекла — уходим на OIDC-логин целиком.
    window.location.href = '/auth/login'
    throw new ApiError(401, 'unauthorized')
  }

  const text = await response.text()
  const retryAfterMs = retryAfterDelay(response.headers.get('Retry-After'))
  let data: unknown = null
  if (text !== '') {
    try {
      data = JSON.parse(text) as unknown
    } catch {
      throw new ApiError(response.status, 'некорректный JSON в ответе API', null, null, retryAfterMs)
    }
  }

  if (!response.ok) {
    const message = isErrorPayload(data) ? data.error : `HTTP ${response.status}`
    throw new ApiError(response.status, message, errorCode(data), data, retryAfterMs)
  }
  return data as T
}

/** POST с необязательным JSON-телом; мутации отвечают 201/202 с JSON. */
export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const options: ApiOptions = { method: 'POST' }
  if (body !== undefined) {
    options.body = body
  }
  return api<T>(path, options)
}

/**
 * POST с сырым телом и явным Content-Type: манифест доступов уходит на
 * /access/plan и /access/apply как есть (JSON или YAML), сериализацию и
 * валидацию выполняет бэкенд.
 */
export function apiPostRaw<T>(
  path: string,
  rawBody: string,
  contentType: string,
): Promise<T> {
  return api<T>(path, { method: 'POST', rawBody, contentType })
}

/**
 * DELETE с необязательными query-параметрами и необязательным JSON-телом
 * (DELETE /accounts/{id}?confirm=true, тело {"reason":"..."}): флаги
 * подтверждения идут в query, пользовательский текст — телом, чтобы не
 * попадать в URL и access-логи.
 */
export function apiDelete<T>(
  path: string,
  query?: Record<string, string>,
  body?: unknown,
): Promise<T> {
  const suffix = query !== undefined ? `?${new URLSearchParams(query).toString()}` : ''
  const options: ApiOptions = { method: 'DELETE' }
  if (body !== undefined) {
    options.body = body
  }
  return api<T>(`${path}${suffix}`, options)
}

/**
 * Разворачивает envelope списковых ответов API:
 * {"connections": [...]} → Connection[].
 */
export async function apiList<T>(
  path: string,
  envelopeKey: string,
  signal?: AbortSignal,
): Promise<T[]> {
  const data = await api<Record<string, unknown>>(path, { signal })
  const items = data[envelopeKey]
  return Array.isArray(items) ? (items as T[]) : []
}

export interface ApiListPage<T> {
  items: T[]
  total: number
  statusTotals?: {
    active: number
    errors: number
    all: number
  }
}

/**
 * Списковый envelope с точным server-side total. В отличие от apiList,
 * сохраняет total независимо от limit/offset текущей страницы.
 */
export async function apiListPage<T>(
  path: string,
  envelopeKey: string,
  signal?: AbortSignal,
): Promise<ApiListPage<T>> {
  const data = await api<Record<string, unknown>>(path, { signal })
  const rawItems = data[envelopeKey]
  const items = Array.isArray(rawItems) ? (rawItems as T[]) : []
  const rawStatusTotals = data.status_totals
  const statusTotalsRecord =
    typeof rawStatusTotals === 'object' && rawStatusTotals !== null
      ? (rawStatusTotals as Record<string, unknown>)
      : null
  const statusTotals =
    statusTotalsRecord !== null
      ? {
          active:
            typeof statusTotalsRecord.active === 'number' ? statusTotalsRecord.active : 0,
          errors:
            typeof statusTotalsRecord.errors === 'number' ? statusTotalsRecord.errors : 0,
          all: typeof statusTotalsRecord.all === 'number' ? statusTotalsRecord.all : 0,
        }
      : undefined
  return {
    items,
    total: typeof data.total === 'number' ? data.total : items.length,
    statusTotals,
  }
}
