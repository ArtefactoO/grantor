import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Binding, Permission, PermissionView, Resource } from '../lib/types'
import { AccountPermissionsSection } from './account-permissions-section'

function view(overrides: Partial<PermissionView> = {}): PermissionView {
  return {
    category: 'role',
    action: '',
    resource: '',
    scope: '',
    dangerous: false,
    danger_reason: '',
    details: null,
    raw: '',
    ...overrides,
  }
}

function permission(id: string, normalized: PermissionView): Permission {
  return {
    id,
    connection_id: 'connection-1',
    engine: 'kafka',
    external_id: id,
    name: normalized.raw,
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: normalized.dangerous,
    attributes: {},
    normalized,
    created_at: '',
    updated_at: '',
  }
}

function binding(permissionId: string, overrides: Partial<Binding> = {}): Binding {
  return {
    id: `binding-${permissionId}`,
    account_id: 'account-1',
    permission_definition_id: permissionId,
    scope_resource_id: null,
    source: 'service',
    desired_state: 'present',
    observed_state: 'present',
    observed_effective: true,
    status: 'synced',
    expires_at: null,
    created_at: '',
    updated_at: '',
    ...overrides,
  }
}

// Длинное ACL-выражение Kafka — тот самый случай, ради которого делалась
// нормализация: подпись короткая, но исходное выражение остаётся доступным.
const longRaw = 'acl:topic:prefixed:project-production-events-stream:read:allow'

const permissions = new Map<string, Permission>([
  [
    'p-long',
    permission(
      'p-long',
      view({
        category: 'acl',
        action: 'read',
        resource: 'project-production-events-stream',
        raw: longRaw,
        details: [
          { key: 'resource_type', value: 'topic' },
          { key: 'pattern', value: 'prefixed' },
        ],
      }),
    ),
  ],
  [
    'p-danger',
    permission(
      'p-danger',
      view({
        category: 'bundle',
        action: 'admin',
        resource: 'kafka-cluster',
        dangerous: true,
        danger_reason: 'grants cluster operations: ALL',
        raw: 'cluster-admin',
      }),
    ),
  ],
])

const resources = new Map<string, Resource>()

function renderSection(bindings: Binding[]) {
  return render(
    <AccountPermissionsSection
      bindings={bindings}
      permissionsById={permissions}
      resourcesById={resources}
      engine="kafka"
      accountLabel="deploy_bot"
    />,
  )
}

describe('AccountPermissionsSection', () => {
  it('свёрнут по умолчанию, но сводка видна всегда', () => {
    renderSection([binding('p-long'), binding('p-danger')])
    const toggle = screen.getByRole('button', { name: /Права доступа/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveTextContent('2 права')
    expect(toggle).toHaveTextContent('опасных: 1')
  })

  // Недостающее право — главный сигнал «доступ не работает», и он обязан
  // быть виден, не раскрывая раздел.
  it('показывает в сводке недостающие права', () => {
    renderSection([binding('p-long', { observed_state: 'absent', status: 'drift' })])
    expect(screen.getByRole('button', { name: /Права доступа/ })).toHaveTextContent(
      'отсутствует: 1',
    )
  })

  it('раскрывается и показывает короткую подпись вместо сырого выражения', async () => {
    const user = userEvent.setup()
    renderSection([binding('p-long')])
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))

    expect(
      screen.getByRole('button', { name: `Подробности права ${longRaw}` }),
    ).toHaveTextContent('read: project-production-events-stream')
  })

  it('открывает подробности мышью и показывает полное выражение', async () => {
    const user = userEvent.setup()
    renderSection([binding('p-long')])
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))
    await user.click(screen.getByRole('button', { name: `Подробности права ${longRaw}` }))

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText(longRaw)).toBeInTheDocument()
    expect(within(drawer).getByText('тип ресурса')).toBeInTheDocument()
  })

  // Клавиатурный путь обязан быть равноправным: право — это кнопка, а не
  // div с обработчиком клика.
  it('открывает подробности с клавиатуры, закрывает Esc и возвращает фокус', async () => {
    const user = userEvent.setup()
    renderSection([binding('p-danger')])
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))

    const chip = screen.getByRole('button', { name: 'Подробности права cluster-admin' })
    chip.focus()
    await user.keyboard('{Enter}')

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('grants cluster operations: ALL')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(chip).toHaveFocus())
  })

  // Наследование показывается только там, где оно есть: у движков без
  // иерархии ролей счётчик был бы постоянным нулём.
  it('показывает унаследованные права и фильтрует по ним', async () => {
    const user = userEvent.setup()
    renderSection([
      binding('p-long'),
      binding('p-danger', { id: 'binding-inherited', source: 'inherited' }),
    ])

    const toggle = screen.getByRole('button', { name: /Права доступа/ })
    expect(toggle).toHaveTextContent('унаследовано: 1')

    await user.click(toggle)
    await user.click(screen.getByRole('button', { name: 'унаследованные' }))
    expect(
      screen.getByRole('button', { name: 'Подробности права cluster-admin' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: `Подробности права ${longRaw}` }),
    ).not.toBeInTheDocument()
  })

  it('фильтрует список по опасным правам', async () => {
    const user = userEvent.setup()
    renderSection([binding('p-long'), binding('p-danger')])
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))

    await user.click(screen.getByRole('button', { name: 'опасные' }))
    expect(
      screen.getByRole('button', { name: 'Подробности права cluster-admin' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: `Подробности права ${longRaw}` }),
    ).not.toBeInTheDocument()
  })

  it('отзывает только управляемое право без открытия деталей или выбора контейнера', async () => {
    const user = userEvent.setup()
    const managed = binding('p-long')
    const onRevoke = vi.fn()
    const onSelect = vi.fn()
    render(<div onClick={onSelect}>
      <AccountPermissionsSection
        bindings={[managed, binding('p-danger', { source: 'discovered', desired_state: null })]}
        permissionsById={permissions}
        resourcesById={resources}
        engine="kafka"
        onRevoke={onRevoke}
      />
    </div>)
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))
    onSelect.mockClear()
    const revoke = screen.getByRole('button', { name: `Снять право ${longRaw}` })
    expect(revoke).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    expect(screen.queryByRole('button', { name: 'Снять право cluster-admin' })).not.toBeInTheDocument()
    revoke.focus()
    await user.keyboard('{Enter}')
    expect(onRevoke).toHaveBeenCalledWith(managed)
    expect(onSelect).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('блокирует повторный отзыв, пока текущая операция выполняется', async () => {
    const user = userEvent.setup()
    const onRevoke = vi.fn()
    render(<AccountPermissionsSection
      bindings={[binding('p-long')]}
      permissionsById={permissions}
      resourcesById={resources}
      engine="kafka"
      onRevoke={onRevoke}
      revokingId="binding-p-long"
    />)
    await user.click(screen.getByRole('button', { name: /Права доступа/ }))
    const revoke = screen.getByRole('button', { name: `Снять право ${longRaw}` })
    expect(revoke).toBeDisabled()
    expect(revoke).toHaveAttribute('aria-busy', 'true')
    await user.click(revoke)
    expect(onRevoke).not.toHaveBeenCalled()
  })
})
