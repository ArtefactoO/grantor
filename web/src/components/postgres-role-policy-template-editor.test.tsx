import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { useState } from 'react'
import type { PostgresRolePolicyTemplate, Resource } from '../lib/types'
import type { PostgresPolicySuggestionSnapshot } from '../lib/postgres-role-policy-suggestions'
import { PostgresRolePolicyTemplateEditor } from './postgres-role-policy-template-editor'
import { pairedPostgresRolePolicyDrafts } from '../lib/postgres-role-policy-templates'

const observedAt = '2026-10-12T09:00:00Z'
const template: PostgresRolePolicyTemplate = {
  key: 'appdb-read', name: 'App DB reader', description: 'For analytics', role_name: 'r_appdb',
  database: 'appdb', schemas: ['public'], owner_roles: ['manual_owner'],
  creator_roles: ['migration_role'], profile: 'read',
}
function resource(id: string, kind: string, name: string, parent: string | null, owner: string): Resource {
  return {
    id, kind, name, parent_id: parent, connection_id: 'connection-1', external_id: id,
    canonical_path: name, attributes: { owner }, fingerprint: id, observed_at: observedAt,
    status: 'observed', ownership: 'unmanaged', created_at: observedAt, updated_at: observedAt,
  }
}
const suggestions: PostgresPolicySuggestionSnapshot = {
  connection: { id: 'connection-1', engine: 'postgres', status: 'active', last_discovery_at: observedAt, topology: {} },
  resources: [
    resource('db', 'database', 'appdb', null, 'database_owner'),
    resource('schema', 'schema', 'public', 'db', 'schema_owner'),
    resource('table', 'table', 'events', 'schema', 'object_owner'),
    resource('empty', 'schema', 'empty', 'db', 'empty_schema_owner'),
    resource('other-db', 'database', 'other_db', null, 'other_database_owner'),
    resource('other-schema', 'schema', 'public', 'other-db', 'other_schema_owner'),
  ],
}

describe('PostgresRolePolicyTemplateEditor', () => {
  it('creates an explicit READ/RW pair as unsaved structured drafts', async () => {
    const onChange = vi.fn()
    render(
      <PostgresRolePolicyTemplateEditor
        templates={[]}
        databaseHint="appdb"
        onChange={onChange}
      />,
    )

    expect(screen.queryByText(/Сохранение каталога/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Черновик пары READ/RW' }))

    expect(onChange).toHaveBeenCalledWith([
      expect.objectContaining({
        key: 'appdb-read',
        role_name: 'r_appdb',
        database: 'appdb',
        schemas: ['public'],
        owner_roles: [],
        creator_roles: [],
        profile: 'read',
      }),
      expect.objectContaining({
        key: 'appdb-read-write',
        role_name: 'rw_appdb',
        database: 'appdb',
        profile: 'read_write',
      }),
    ])
  })

  it('keeps owner and creator roles as separate structured fields', async () => {
    const onChange = vi.fn()
    render(
      <PostgresRolePolicyTemplateEditor
        templates={[{
          key: 'appdb-read',
          name: 'App DB — чтение',
          description: 'Для аналитики',
          role_name: 'r_appdb',
          database: 'appdb',
          schemas: ['public'],
          owner_roles: ['app_owner'],
          creator_roles: ['app_migrations'],
          profile: 'read',
        }]}
        onChange={onChange}
      />,
    )

    const creators = screen.getByRole('textbox', { name: /^Creator-роли/ })
    fireEvent.change(creators, { target: { value: 'app_migrations\nreport_builder' } })

    expect(onChange).toHaveBeenLastCalledWith([
      expect.objectContaining({
        owner_roles: ['app_owner'],
        creator_roles: ['app_migrations', 'report_builder'],
      }),
    ])
  })

  it('sanitizes role draft identifiers and leaves them empty without a database hint', async () => {
    const onChange = vi.fn()
    const { rerender } = render(
      <PostgresRolePolicyTemplateEditor
        templates={[]}
        databaseHint="sample.db-data"
        onChange={onChange}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: 'Черновик пары READ/RW' }))
    expect(onChange).toHaveBeenLastCalledWith([
      expect.objectContaining({ role_name: 'r_sample_db_data' }),
      expect.objectContaining({ role_name: 'rw_sample_db_data' }),
    ])

    onChange.mockClear()
    rerender(
      <PostgresRolePolicyTemplateEditor templates={[]} databaseHint="" onChange={onChange} />,
    )
    await userEvent.click(screen.getByRole('button', { name: 'Черновик пары READ/RW' }))
    expect(onChange).toHaveBeenLastCalledWith([
      expect.objectContaining({ role_name: '' }),
      expect.objectContaining({ role_name: '' }),
    ])
  })

  it('adds explicitly selected owner/creator candidates without replacing manual roles or creating target actions', async () => {
    const onChange = vi.fn()
    function Editor() {
      const [templates, setTemplates] = useState([template])
      return <PostgresRolePolicyTemplateEditor
        templates={templates} connectionId="connection-1" suggestionSnapshot={suggestions}
        onChange={(value) => { onChange(value); setTemplates(value) }}
      />
    }
    render(<Editor />)

    expect(onChange).not.toHaveBeenCalled()
    expect(screen.getByText(/Она не определяет будущего создателя/)).toBeInTheDocument()
    expect(screen.getByText('Владелец объектов: public (1).')).toBeInTheDocument()
    expect(screen.getByText(/несколько владельцев/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Добавить database_owner/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Применить/ })).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Добавить object_owner в Owner-роли' }))
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('manual_owner\nobject_owner')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('migration_role')
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Owner-роли' })).toBeDisabled()

    await userEvent.click(screen.getByRole('button', { name: 'Добавить schema_owner в Creator-роли' }))
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('migration_role\nschema_owner')
    expect(onChange).toHaveBeenLastCalledWith([expect.objectContaining({
      owner_roles: ['manual_owner', 'object_owner'], creator_roles: ['migration_role', 'schema_owner'],
    })])
  })

  it('updates scoped evidence when database/schemas change while retaining manual fields', () => {
    function Editor() {
      const [templates, setTemplates] = useState([template])
      return <PostgresRolePolicyTemplateEditor templates={templates} onChange={setTemplates}
        connectionId="connection-1" suggestionSnapshot={suggestions} />
    }
    render(<Editor />)
    fireEvent.change(screen.getByRole('textbox', { name: /^Схемы/ }), { target: { value: 'empty' } })
    expect(screen.queryByRole('button', { name: /Добавить object_owner/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Добавить empty_schema_owner в Owner-роли' })).toBeInTheDocument()
    expect(screen.getByText(/роль будущих миграций укажите отдельно/)).toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: 'База данных' }), { target: { value: 'other_db' } })
    expect(screen.getByText(/Схема empty отсутствует/)).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /^Схемы/ }), { target: { value: 'public' } })
    expect(screen.getByRole('button', { name: 'Добавить other_schema_owner в Owner-роли' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Добавить empty_schema_owner/ })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('manual_owner')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('migration_role')
  })

  it('explains missing target evidence and blocks stale, failed or loading suggestions without blocking manual editing', () => {
    const onChange = vi.fn()
    const props = { templates: [template], onChange, connectionId: 'connection-1', onLoadSuggestions: vi.fn() }
    const { rerender } = render(<PostgresRolePolicyTemplateEditor {...props} />)
    expect(screen.getByRole('button', { name: 'Загрузить подсказки Owner/Creator' })).toBeEnabled()
    rerender(<PostgresRolePolicyTemplateEditor {...props} suggestionSnapshot={{
      ...suggestions, resources: suggestions.resources.map((item) => ({ ...item, observed_at: '2026-10-11T09:00:00Z' })),
    }} />)
    expect(screen.getByText(/Снимок базы устарел/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Добавить object_owner/ })).not.toBeInTheDocument()
    rerender(<PostgresRolePolicyTemplateEditor {...props} suggestionSnapshot={suggestions} suggestionsPending />)
    expect(screen.getByRole('button', { name: 'Загрузка подсказок…' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Добавить object_owner/ })).not.toBeInTheDocument()
    rerender(<PostgresRolePolicyTemplateEditor {...props} suggestionSnapshot={suggestions} suggestionsError="HTTP 503" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Повторите загрузку')
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toBeEnabled()
    fireEvent.change(screen.getByRole('textbox', { name: /^Owner-роли/ }), { target: { value: 'new_manual' } })
    expect(onChange).toHaveBeenCalledWith([expect.objectContaining({ owner_roles: ['new_manual'] })])
  })

  it('accepts all observed owners in one action while preserving a separately selected migration role', async () => {
    const onChange = vi.fn()
    function Editor() {
      const [templates, setTemplates] = useState([template])
      return <PostgresRolePolicyTemplateEditor
        templates={templates} connectionId="connection-1" suggestionSnapshot={suggestions}
        onChange={(value) => { onChange(value); setTemplates(value) }}
      />
    }
    render(<Editor />)
    await userEvent.click(screen.getByRole('button', { name: 'Добавить всех владельцев' }))
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('manual_owner\nobject_owner\nschema_owner')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('migration_role')
    expect(screen.getByRole('button', { name: 'Все владельцы добавлены' })).toBeDisabled()
  })

  it('never adds the policy role as its own owner or exceeds the role list bound', () => {
    const { rerender } = render(<PostgresRolePolicyTemplateEditor templates={[{ ...template, role_name: 'object_owner' }]}
      onChange={vi.fn()} connectionId="connection-1" suggestionSnapshot={suggestions} />)
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Owner-роли' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Creator-роли' })).toBeDisabled()
    rerender(<PostgresRolePolicyTemplateEditor templates={[{
      ...template, owner_roles: Array.from({ length: 64 }, (_item, index) => `owner_${index}`),
    }]} onChange={vi.fn()} connectionId="connection-1" suggestionSnapshot={suggestions} />)
    expect(screen.getByRole('button', { name: 'Добавить всех владельцев' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Owner-роли' })).toBeDisabled()
  })

  it('preserves unchanged templates and scope array identities while editing another field', () => {
    const second = { ...template, key: 'appdb-write', role_name: 'rw_appdb', profile: 'read_write' as const }
    const original = [template, second]
    const onChange = vi.fn()
    render(<PostgresRolePolicyTemplateEditor templates={original} onChange={onChange}
      connectionId="connection-1" suggestionSnapshot={suggestions} />)
    fireEvent.change(screen.getAllByRole('textbox', { name: 'Название' })[0], { target: { value: 'Updated reader' } })
    const changed = onChange.mock.calls[0][0] as PostgresRolePolicyTemplate[]
    expect(changed).not.toBe(original)
    expect(changed[0]).not.toBe(template)
    expect(changed[0].name).toBe('Updated reader')
    expect(changed[0].schemas).toBe(template.schemas)
    expect(changed[0].owner_roles).toBe(template.owner_roles)
    expect(changed[0].creator_roles).toBe(template.creator_roles)
    expect(changed[1]).toBe(second)
    expect(template.name).toBe('App DB reader')
  })

  it('edits a new READ/RW pair with one set of scope fields and preserves independent metadata', () => {
    const initial = pairedPostgresRolePolicyDrafts('appdb').map((draft, index) => ({
      ...draft, description: `Role ${index}`, owner_roles: ['manual_owner'], creator_roles: ['migration_role'],
    }))
    const onChange = vi.fn()
    function Editor() {
      const [templates, setTemplates] = useState(initial)
      return <PostgresRolePolicyTemplateEditor templates={templates} initialPair
        onChange={(value) => { onChange(value); setTemplates(value) }} />
    }
    render(<Editor />)
    for (const name of ['База данных', /^Схемы/, /^Owner-роли/, /^Creator-роли/]) {
      expect(screen.getAllByRole('textbox', { name })).toHaveLength(1)
    }
    expect(screen.getByRole('textbox', { name: 'READ · NOLOGIN-роль' })).toHaveValue('r_appdb')
    expect(screen.getByRole('textbox', { name: 'RW · NOLOGIN-роль' })).toHaveValue('rw_appdb')
    expect(screen.getByText('READ + INSERT, UPDATE, DELETE')).toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: 'База данных' }), { target: { value: 'reporting' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Схемы/ }), { target: { value: 'reports\naudit' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Owner-роли/ }), { target: { value: 'manual_owner\nreport_owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Creator-роли/ }), { target: { value: 'migration_role\nreport_migrations' } })
    const changed = onChange.mock.lastCall?.[0] as PostgresRolePolicyTemplate[]
    expect(changed).toEqual(initial.map((draft) => ({
      ...draft, database: 'reporting', schemas: ['reports', 'audit'],
      owner_roles: ['manual_owner', 'report_owner'], creator_roles: ['migration_role', 'report_migrations'],
    })))
    expect(initial[0].database).toBe('appdb')
    expect(initial[1].creator_roles).toEqual(['migration_role'])
  })

  it('accepts suggestions once for both drafts without guessing future creators or adding either policy role', async () => {
    const initial = pairedPostgresRolePolicyDrafts('appdb').map((draft, index) => ({
      ...draft, description: 'Pair policy', owner_roles: ['manual_owner'], creator_roles: ['migration_role'],
      role_name: index === 1 ? 'object_owner' : draft.role_name,
    }))
    const onChange = vi.fn()
    function Editor() {
      const [templates, setTemplates] = useState(initial)
      return <PostgresRolePolicyTemplateEditor templates={templates} initialPair
        connectionId="connection-1" suggestionSnapshot={suggestions}
        onChange={(value) => { onChange(value); setTemplates(value) }} />
    }
    render(<Editor />)
    expect(onChange).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Owner-роли' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Добавить object_owner в Creator-роли' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Добавить всех владельцев' }))
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(onChange).toHaveBeenLastCalledWith(initial.map((draft) => ({
      ...draft, owner_roles: ['manual_owner', 'schema_owner'],
    })))
    await userEvent.click(screen.getByRole('button', { name: 'Добавить schema_owner в Creator-роли' }))
    expect(onChange).toHaveBeenLastCalledWith(initial.map((draft) => ({
      ...draft, owner_roles: ['manual_owner', 'schema_owner'], creator_roles: ['migration_role', 'schema_owner'],
    })))
  })

  it('renders one arbitrary template at a time and retains differing scopes and edits when switching', async () => {
    const second = {
      ...template, key: 'reports-write', name: 'Reports writer', role_name: 'rw_reports',
      database: 'reports', schemas: ['audit'], owner_roles: ['report_owner'],
      creator_roles: ['report_migrations'], profile: 'read_write' as const,
    }
    const onChange = vi.fn()
    function Editor() {
      const [templates, setTemplates] = useState([template, second])
      return <PostgresRolePolicyTemplateEditor templates={templates}
        onChange={(value) => { onChange(value); setTemplates(value) }} />
    }
    render(<Editor />)
    expect(screen.getAllByRole('textbox', { name: 'Название' })).toHaveLength(1)
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Edited reader' } })
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать шаблон: Reports writer' }))
    expect(screen.getByRole('textbox', { name: 'База данных' })).toHaveValue('reports')
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('report_owner')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('report_migrations')
    fireEvent.change(screen.getByRole('textbox', { name: /^Схемы/ }), { target: { value: 'audit\nexports' } })
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать шаблон: Edited reader' }))
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Edited reader')
    expect(screen.getByRole('textbox', { name: 'База данных' })).toHaveValue('appdb')
    expect(screen.getByRole('textbox', { name: /^Схемы/ })).toHaveValue('public')
    expect(onChange).toHaveBeenLastCalledWith([
      { ...template, name: 'Edited reader' }, { ...second, schemas: ['audit', 'exports'] },
    ])
  })

  it('does not share matching existing scopes or coerce different scopes from an imported pair', async () => {
    const drafts = pairedPostgresRolePolicyDrafts('appdb').map((draft) => ({ ...draft, description: 'Existing policy' }))
    const onChange = vi.fn()
    const { rerender } = render(<PostgresRolePolicyTemplateEditor templates={drafts} onChange={onChange} />)
    expect(screen.queryByRole('textbox', { name: 'READ · NOLOGIN-роль' })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'База данных' }), { target: { value: 'changed_only_read' } })
    expect(onChange).toHaveBeenLastCalledWith([{ ...drafts[0], database: 'changed_only_read' }, drafts[1]])

    const differing = [{ ...drafts[0], schemas: ['analytics'] }, { ...drafts[1], creator_roles: ['writer_migrations'] }]
    rerender(<PostgresRolePolicyTemplateEditor key="imported" templates={differing} initialPair onChange={onChange} />)
    expect(screen.getByText(/Их различия сохраняются/)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /^Схемы/ })).toHaveValue('analytics')
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать шаблон: appdb: чтение и запись' }))
    expect(screen.getByRole('textbox', { name: /^Схемы/ })).toHaveValue('public')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('writer_migrations')
    expect(onChange).toHaveBeenCalledTimes(1)
  })

  it('can separate a draft pair explicitly without changing its payload', async () => {
    const drafts = pairedPostgresRolePolicyDrafts('appdb').map((draft) => ({ ...draft, description: 'Pair policy' }))
    const onChange = vi.fn()
    render(<PostgresRolePolicyTemplateEditor templates={drafts} initialPair onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать отдельно' }))
    expect(onChange).not.toHaveBeenCalled()
    expect(screen.getByRole('textbox', { name: 'NOLOGIN-роль' })).toHaveValue('r_appdb')
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать шаблон: appdb: чтение и запись' }))
    fireEvent.change(screen.getByRole('textbox', { name: /^Creator-роли/ }), { target: { value: 'only_writer' } })
    expect(onChange).toHaveBeenLastCalledWith([drafts[0], { ...drafts[1], creator_roles: ['only_writer'] }])
  })

  it('opts template and suggestion actions into touch targets without changing desktop button size', () => {
    render(<PostgresRolePolicyTemplateEditor templates={[template]} onChange={vi.fn()}
      connectionId="connection-1" suggestionSnapshot={suggestions} onLoadSuggestions={vi.fn()} />)
    for (const name of [
      'Черновик пары READ/RW', 'Добавить одну', 'Обновить подсказки Owner/Creator',
      'Добавить всех владельцев', 'Добавить object_owner в Owner-роли', 'Добавить object_owner в Creator-роли',
      'Удалить policy: App DB reader',
    ]) {
      expect(screen.getByRole('button', { name })).toHaveClass('grantor-touch-target', 'h-7')
    }
  })
})
