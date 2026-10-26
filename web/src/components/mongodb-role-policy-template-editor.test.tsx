import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { MongoDBRolePolicyTemplate } from '../lib/types'
import { MongoDBRolePolicyTemplateEditor } from './mongodb-role-policy-template-editor'

function template(overrides: Partial<MongoDBRolePolicyTemplate> = {}): MongoDBRolePolicyTemplate {
  return {
    key: 'etl-reader',
    name: 'ETL reader',
    description: 'Read event data',
    role_name: 'etlReader',
    role_database: 'appdb',
    inherited_roles: [{ role: 'read', db: 'appdb' }],
    privileges: [{
      resource: { db: 'appdb', collection: 'events' },
      actions: ['find'],
    }],
    ...overrides,
  }
}

async function expandTemplate(
  user: ReturnType<typeof userEvent.setup>,
  name = 'ETL reader',
) {
  await user.click(screen.getByRole('button', { name: `Развернуть Policy: ${name}` }))
}

describe('MongoDBRolePolicyTemplateEditor', () => {
  it('creates a typed draft without raw BSON or arbitrary command controls', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(
      <MongoDBRolePolicyTemplateEditor
        templates={[]}
        databaseHint="appdb"
        onChange={onChange}
      />,
    )

    expect(screen.getByText(/Built-in read\/readWrite/)).toBeVisible()
    expect(screen.queryByRole('textbox', { name: /BSON|JSON|command/i })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Добавить policy' }))
    expect(onChange).toHaveBeenCalledWith([
      expect.objectContaining({
        role_database: 'appdb',
        inherited_roles: [],
        privileges: [],
      }),
    ])
  })

  it('uses a searchable allowlist and prevents cluster scope for a non-admin role', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<MongoDBRolePolicyTemplateEditor templates={[template()]} onChange={onChange} />)
    const disclosure = screen.getByRole('button', { name: 'Развернуть Policy: ETL reader' })
    const metaId = disclosure.getAttribute('aria-describedby')
    expect(metaId).not.toBeNull()
    expect(document.getElementById(metaId ?? '')).toHaveTextContent('appdb.etlReader; 1 privileges')
    await expandTemplate(user)
    await user.click(screen.getByRole('button', { name: /Развернуть Privilege 1:/ }))

    const resource = screen.getByRole('combobox', { name: 'Resource 1' })
    await user.click(resource)
    expect(screen.queryByText('Any resource')).not.toBeInTheDocument()
    expect(screen.getByText('Cluster').closest('[data-disabled=true]')).toBeInTheDocument()
    await user.keyboard('{Escape}')

    await user.click(screen.getByRole('combobox', { name: 'Actions 1' }))
    expect(screen.getAllByText('find').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Data access').length).toBeGreaterThan(0)
    expect(screen.queryByText('anyAction')).not.toBeInTheDocument()
  })

  it('shows an explicit dangerous preview for an admin cluster policy', async () => {
    const user = userEvent.setup()
    render(
      <MongoDBRolePolicyTemplateEditor
        templates={[template({
          role_database: 'admin',
          inherited_roles: [],
          privileges: [{ resource: { cluster: true }, actions: ['serverStatus'] }],
        })]}
        onChange={() => undefined}
      />,
    )
    await expandTemplate(user)

    expect(screen.getByText('Предварительный dangerous preview')).toBeVisible()
    expect(screen.getByText('Есть действие на cluster-wide resource.')).toBeVisible()
    expect(screen.getByText(/Итоговый dangerous вычисляет adapter/)).toBeVisible()
  })

  it('pins a new inherited role to role_database outside admin', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(
      <MongoDBRolePolicyTemplateEditor
        templates={[template({ inherited_roles: [] })]}
        onChange={onChange}
      />,
    )

    await expandTemplate(user)
    await user.click(screen.getByRole('button', { name: 'Добавить роль в policy ETL reader' }))
    expect(onChange).toHaveBeenCalledWith([
      expect.objectContaining({ inherited_roles: [{ role: '', db: 'appdb' }] }),
    ])
  })

  it('removes only the addressed inherited role and privilege', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(
      <MongoDBRolePolicyTemplateEditor
        templates={[template({
          inherited_roles: [
            { role: 'read', db: 'appdb' },
            { role: 'readWrite', db: 'appdb' },
          ],
          privileges: [
            { resource: { db: 'appdb', collection: 'events' }, actions: ['find'] },
            { resource: { db: 'appdb', collection: 'results' }, actions: ['insert'] },
          ],
        })]}
        onChange={onChange}
      />,
    )
    await expandTemplate(user)

    await user.click(screen.getByRole('button', { name: /Удалить наследуемую роль 1/ }))
    expect(onChange).toHaveBeenLastCalledWith([
      expect.objectContaining({ inherited_roles: [{ role: 'readWrite', db: 'appdb' }] }),
    ])

    await user.click(screen.getByRole('button', { name: /Развернуть Privilege 2:/ }))
    await user.click(screen.getByRole('button', { name: /Удалить privilege 2/ }))
    expect(onChange).toHaveBeenLastCalledWith([
      expect.objectContaining({
        privileges: [{
          resource: { db: 'appdb', collection: 'events' },
          actions: ['find'],
        }],
      }),
    ])
  })

  it('keeps the 64x128 worst-case catalog DOM bounded until rows are expanded', async () => {
    const privileges = Array.from({ length: 128 }, (_, index) => ({
      resource: { db: 'appdb', collection: `collection_${index}` },
      actions: ['find'],
    }))
    const templates = Array.from({ length: 64 }, (_, index) => template({
      key: `policy-${index}`,
      name: `Policy ${index + 1}`,
      role_name: `role_${index}`,
      inherited_roles: [],
      privileges,
    }))
    const user = userEvent.setup()
    const { container } = render(
      <MongoDBRolePolicyTemplateEditor templates={templates} onChange={() => undefined} />,
    )

    expect(screen.queryAllByRole('combobox')).toHaveLength(0)
    expect(container.querySelectorAll('*').length).toBeLessThan(1_000)

    await expandTemplate(user, 'Policy 1')
    expect(screen.queryAllByRole('combobox')).toHaveLength(0)
    expect(screen.getAllByRole('button', { name: /Развернуть Privilege/ })).toHaveLength(128)
    expect(container.querySelectorAll('*').length).toBeLessThan(2_000)

    await user.click(screen.getByRole('button', { name: /Развернуть Privilege 1:/ }))
    expect(screen.getAllByRole('combobox')).toHaveLength(2)
    expect(screen.queryByText('addShard')).not.toBeInTheDocument()
  })

  it('force-opens only the first invalid template and first invalid privilege', () => {
    const invalidPrivileges = Array.from({ length: 128 }, (_, index) => ({
      resource: { db: 'appdb', collection: `collection_${index}` },
      actions: [],
    }))
    const templates = Array.from({ length: 64 }, (_, index) => template({
      key: `invalid-${index}`,
      name: `Invalid policy ${index + 1}`,
      role_name: `invalid_role_${index}`,
      inherited_roles: [],
      privileges: invalidPrivileges,
    }))
    const { container } = render(
      <MongoDBRolePolicyTemplateEditor templates={templates} onChange={() => undefined} />,
    )

    expect(screen.getByRole('button', { name: 'Свернуть Policy: Invalid policy 1' }))
      .toHaveAttribute('aria-expanded', 'true')
    expect(screen.getAllByRole('button', { name: /Развернуть Policy:/ })).toHaveLength(63)
    expect(screen.getByRole('button', { name: /Свернуть Privilege 1:/ }))
      .toHaveAttribute('aria-expanded', 'true')
    expect(screen.getAllByRole('button', { name: /Развернуть Privilege/ })).toHaveLength(127)
    expect(screen.getAllByRole('combobox')).toHaveLength(2)
    expect(screen.queryByText('addShard')).not.toBeInTheDocument()
    expect(container.querySelectorAll('*').length).toBeLessThan(2_500)
  })

  it('preserves structural sharing for untouched templates and nested arrays', async () => {
    const first = template()
    const second = template({ key: 'writer', name: 'Writer', role_name: 'writer' })
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(
      <MongoDBRolePolicyTemplateEditor templates={[first, second]} onChange={onChange} />,
    )

    await expandTemplate(user)
    fireEvent.change(screen.getByRole('textbox', { name: /^Название/ }), {
      target: { value: 'Updated reader' },
    })

    const next = onChange.mock.calls[0]?.[0] as MongoDBRolePolicyTemplate[]
    expect(next[1]).toBe(second)
    expect(next[0]?.privileges).toBe(first.privileges)
    expect(next[0]?.inherited_roles).toBe(first.inherited_roles)
  })
})
