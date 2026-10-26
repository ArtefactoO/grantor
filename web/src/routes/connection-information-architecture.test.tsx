import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ScopeEnforcementStatus } from './scope-policies'

describe('scope enforcement runtime status', () => {
  it('does not infer enforcement from the policy list when API has no field', () => {
    render(<ScopeEnforcementStatus state={{ kind: 'unavailable' }} />)

    expect(screen.getByText('Режим ограничения доступа')).toBeInTheDocument()
    expect(screen.getByText('Unavailable')).toBeInTheDocument()
    expect(
      screen.getByText(/Сохранённые правила могут не применяться/),
    ).toBeInTheDocument()
  })

  it.each([
    ['enforce' as const, 'Enabled', /Без разрешения доступ закрыт/],
    ['disabled' as const, 'Disabled', /сейчас не ограничивают доступ/],
  ])('renders the factual %s runtime value', (mode, label, description) => {
    render(<ScopeEnforcementStatus state={{ kind: 'ready', mode }} />)

    expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.getByText(description)).toBeInTheDocument()
  })
})
