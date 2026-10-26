import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Operation } from '../lib/types'

const apiMock = vi.fn().mockResolvedValue({})
vi.mock('../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/api')>()
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) }
})

import { ApprovalDecisionDialog } from './control'

describe('Control approval confirmation', () => {
  it('requires an explicit second confirmation for self-approval', async () => {
    const operation = {
      id: 'operation-1', kind: 'binding.revoke', actor_id: 'admin@example.test',
      status: 'pending_approval',
    } as Operation
    const onDone = vi.fn()
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ApprovalDecisionDialog operation={operation} decision="approve"
          currentActor="admin@example.test" onClose={vi.fn()} onDone={onDone} />
      </QueryClientProvider>,
    )

    expect(screen.getByText(/это ваш собственный запрос/i)).toBeInTheDocument()
    expect(apiMock).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить и выполнить' }))
    expect(apiMock).toHaveBeenCalledWith('/api/v1/operations/operation-1/approve', { method: 'POST' })
    expect(onDone).toHaveBeenCalledOnce()
  })
})
