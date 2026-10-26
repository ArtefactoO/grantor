/**
 * Copies text without exposing it to logs or application state.
 * Clipboard API is preferred; the fallback keeps local HTTP/dev environments
 * usable when the secure-context API is unavailable.
 */
export async function copyText(text: string): Promise<void> {
  if (typeof navigator.clipboard?.writeText === 'function') {
    await navigator.clipboard.writeText(text)
    return
  }

  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  area.style.pointerEvents = 'none'
  document.body.appendChild(area)
  try {
    area.select()
    if (!document.execCommand('copy')) {
      throw new Error('copy command rejected')
    }
  } finally {
    area.remove()
  }
}
