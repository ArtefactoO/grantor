import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AuditEvent } from '../lib/types'
import { AuditAccessContext } from './control'

const event = (overrides: Partial<AuditEvent> = {}): AuditEvent => ({
  id: 3,
  occurred_at: '2026-07-28T19:16:06Z',
  actor_type: 'service',
  actor_id: 'grantor-maintenance',
  action: 'principal.external_identity_status_changed',
  connection_id: null,
  resource_id: null,
  principal_id: 'principal-1',
  account_id: null,
  operation_id: null,
  result: 'success',
  metadata: { provider: 'authentik', status: 'active', previous_status: null, reason: 'active' },
  ...overrides,
})

describe('карточка события аудита', () => {
  it('раскрывает контекст каталога понятными подписями', () => {
    render(<AuditAccessContext event={event()} />)

    expect(screen.getByText('Каталог')).toBeInTheDocument()
    expect(screen.getByText('authentik')).toBeInTheDocument()
    expect(screen.getByText('Статус')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  // reason у событий каталога дублирует новый статус, и подпись «Причина:
  // active» читалась как причина изменения, а не как его результат.
  it('не дублирует статус строкой «Причина»', () => {
    render(<AuditAccessContext event={event()} />)

    expect(screen.queryByText('Причина')).not.toBeInTheDocument()
  })

  it('показывает причину, когда она несёт свой смысл', () => {
    render(<AuditAccessContext event={event({
      metadata: { provider: 'authentik', status: 'disabled', reason: 'missing_in_directory' },
    })} />)

    expect(screen.getByText('Причина')).toBeInTheDocument()
    expect(screen.getByText('missing_in_directory')).toBeInTheDocument()
  })
})
