import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from './api'
import { sendAttentionDecision } from './attention-request'

function response(status: number, retryAfter?: string, body = JSON.stringify({ error: 'rate limit exceeded' })) {
  return new Response(body, { status, headers: retryAfter === undefined ? {} : { 'Retry-After': retryAfter } })
}

describe('attention request backpressure', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-14T10:00:00Z')) })
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers() })

  it.each([
    ['2', 2000], ['0', 0], [undefined, null], ['-1', null], ['0.5', null], ['invalid', null],
    ['Mon, 14 Sep 2026 10:00:03 GMT', 3000],
  ])('preserves Retry-After %s without retrying api() itself', async (header, delay) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(429, header as string | undefined))
    await expect(api('/api/v1/operations/id/resolve', { method: 'POST' })).rejects.toMatchObject({ status: 429, retryAfterMs: delay })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each(['resolve', 'approve', 'reject'])('honors Retry-After for %s, including non-JSON 429', async (action) => {
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(429, '2', 'too many requests'))
      .mockResolvedValueOnce(response(200, undefined, '{}'))
    const onWait = vi.fn()
    const done = sendAttentionDecision(`/api/v1/operations/id/${action}`, new AbortController().signal, onWait)
    await vi.advanceTimersByTimeAsync(0)
    expect(onWait).toHaveBeenCalledWith(2000)
    await vi.advanceTimersByTimeAsync(1999)
    expect(fetch).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    await done
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(onWait).toHaveBeenLastCalledWith(null)
  })

  it.each([403, 409, 500, 502])('does not retry status %s after a possibly executed decision', async (status) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(status, '1'))
    await expect(sendAttentionDecision('/api/v1/operations/id/approve', new AbortController().signal, vi.fn())).rejects.toMatchObject({ status })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('does not retry an ambiguous network error', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('connection lost'))
    await expect(sendAttentionDecision('/api/v1/operations/id/approve', new AbortController().signal, vi.fn())).rejects.toMatchObject({ status: 0 })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('bounds repeated throttling and backs off without a Retry-After header', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => response(429))
    const checked = expect(sendAttentionDecision('/api/v1/operations/id/resolve', new AbortController().signal, vi.fn())).rejects.toBeInstanceOf(ApiError)
    await vi.advanceTimersByTimeAsync(4000)
    await checked
    expect(fetch).toHaveBeenCalledTimes(4)
  })
})
