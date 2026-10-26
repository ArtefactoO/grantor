import { api, ApiError } from './api'

// API DefaultRateLimitConfig allows 2 mutations/s per subject across replicas.
// Space decisions even when the requests themselves complete immediately.
export const ATTENTION_REQUEST_INTERVAL_MS = 500
const MAX_RATE_LIMIT_RETRIES = 3
const MAX_RATE_LIMIT_WAIT_MS = 60_000

export function waitForAttentionRequest(ms: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const aborted = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', aborted)
      resolve()
    }, ms)
    signal.addEventListener('abort', aborted, { once: true })
  })
}

/** Retry only the rejected decision, never a possibly executed POST. The API
 * mutation limiter emits 429 before calling approve/reject/resolve handlers. */
export async function sendAttentionDecision(path: string, signal: AbortSignal, onWait: (ms: number | null) => void): Promise<void> {
  let waited = 0
  for (let retry = 0; ; retry++) {
    signal.throwIfAborted()
    try {
      await api(path, { method: 'POST', signal })
      return
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 429) throw error
      const delay = Math.max(error.retryAfterMs ?? 1000, 1000)
      // Never shorten Retry-After. Leave this and remaining rows selected if
      // the server keeps throttling or asks for a long pause.
      if (retry >= MAX_RATE_LIMIT_RETRIES || waited + delay > MAX_RATE_LIMIT_WAIT_MS) throw error
      waited += delay
      onWait(delay)
      try {
        await waitForAttentionRequest(delay, signal)
      } finally {
        onWait(null)
      }
    }
  }
}
