import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { RabbitMQPermissionTemplateEditor } from './rabbitmq-permission-template-editor'

describe('RabbitMQPermissionTemplateEditor', () => {
  it('adds a structured template without exposing an assignment-time raw regex action', async () => {
    const onChange = vi.fn()
    render(<RabbitMQPermissionTemplateEditor templates={[]} onChange={onChange} />)

    expect(screen.getByText(/Legacy-права полного доступа/)).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Добавить' }))
    expect(onChange).toHaveBeenCalledWith([
      expect.objectContaining({ key: '', configure: '^$', write: '^$', read: '^$', dangerous: false }),
    ])
  })

  it('marks broad patterns and removes only the selected template', async () => {
    const onChange = vi.fn()
    render(
      <RabbitMQPermissionTemplateEditor
        templates={[
          { key: 'all', name: 'All', description: '', vhost: 'app', configure: '.*', write: '^x$', read: '^x$', dangerous: true },
          { key: 'read', name: 'Read', description: '', vhost: 'app', configure: '^$', write: '^$', read: '^x$', dangerous: false },
        ]}
        onChange={onChange}
      />,
    )

    expect(screen.getByText(/Broad:/)).toBeVisible()
    await userEvent.click(screen.getAllByRole('button', { name: 'Удалить' })[0])
    expect(onChange).toHaveBeenCalledWith([
      expect.objectContaining({ key: 'read' }),
    ])
  })
})
