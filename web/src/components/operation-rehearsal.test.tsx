import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { OperationRehearsal } from './operation-rehearsal'

describe('OperationRehearsal', () => {
  it('keeps the preview explicitly read-only and exposes the affected scope', () => {
    render(
      <OperationRehearsal
        title="Отзыв роли"
        detail="Роль будет снята после подтверждения."
        impact={<span>local-ui-review · DEV · −1 роль</span>}
      />,
    )

    const preview = screen.getByRole('region', { name: 'Репетиция изменения' })
    expect(preview).toHaveTextContent('Отзыв роли')
    expect(preview).not.toHaveTextContent('Без изменений')
    expect(preview).toHaveTextContent('local-ui-review · DEV · −1 роль')
    expect(withinButtons(preview)).toHaveLength(0)
  })
})

function withinButtons(element: HTMLElement): HTMLButtonElement[] {
  return Array.from(element.querySelectorAll('button'))
}
