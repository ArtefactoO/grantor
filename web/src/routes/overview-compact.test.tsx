import type { ReactNode } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a href="/control?tab=attention" className={className}>{children}</a>
  ),
}))
import { OverviewHealthStrip } from './overview'

describe('compact overview health strip', () => {
  it('keeps the healthy state to one line and moves the explanation to a tooltip', async () => {
    const user = userEvent.setup()
    render(<OverviewHealthStrip attention={0} pendingApproval={0} errors={0} />)

    expect(screen.getByText('Healthy')).toBeVisible()
    expect(screen.getByText('Healthy').closest('span')).toHaveClass('rounded-full')
    expect(screen.queryByText('Проблемных подключений нет.')).not.toBeInTheDocument()

    await user.hover(screen.getByLabelText('Подробнее о состоянии'))
    expect(await screen.findByRole('tooltip')).toHaveTextContent(
      'Проблемных подключений нет. Ожидающих подтверждения операций нет. Ошибок операций нет.',
    )
  })

  it('surfaces failed operations instead of reporting a healthy overview', () => {
    render(<OverviewHealthStrip attention={0} pendingApproval={0} errors={3} />)

    expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
    expect(screen.getByText(/3 ошибок/)).toBeVisible()
    expect(screen.getByRole('link', { name: /Открыть контроль/ })).toHaveAttribute(
      'href',
      '/control?tab=attention',
    )
    expect(screen.getByRole('link', { name: /Открыть контроль/ }))
      .toHaveClass('ui-control-feedback', 'grantor-touch-target')
  })
})
