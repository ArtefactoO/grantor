import { useEffect, useState } from 'react'

const WIDE_INSPECTOR_QUERY = '(min-width: 1024px)'

/** Matches the Tailwind `lg` breakpoint used by responsive inspectors. */
export function useWideInspector() {
  const [wide, setWide] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(WIDE_INSPECTOR_QUERY).matches
      : false,
  )

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return

    const query = window.matchMedia(WIDE_INSPECTOR_QUERY)
    const update = () => setWide(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  return wide
}
