import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import {
  CopyableValue,
  identifierWrapSegments,
  TableCopyableValue,
} from './copyable-value'

describe('CopyableValue', () => {
  it('keeps long values wrappable and the copy action available to touch and desktop input', () => {
    render(
      <CopyableValue
        value="service_animation_board@animation_board"
        label="Копировать имя аккаунта"
        fill
      />,
    )

    expect(screen.getByText('service_animation_board@animation_board')).toHaveClass(
      '[overflow-wrap:anywhere]', 'flex-1',
    )
    expect(screen.getByText('service_animation_board@animation_board').parentElement)
      .toHaveClass('flex', 'w-full')
    expect(screen.getByRole('button', { name: 'Копировать имя аккаунта' })).toBeInTheDocument()
    const action = screen.getByText('service_animation_board@animation_board').nextElementSibling
    expect(action).not.toHaveClass('pointer-events-none', 'opacity-0')
    expect(action).toHaveClass(
      '[@media(hover:hover)]:pointer-events-none',
      '[@media(hover:hover)]:opacity-0',
      '[@media(hover:hover)]:group-hover/copyable:pointer-events-auto',
      '[@media(hover:hover)]:group-hover/copyable:opacity-100',
      '[@media(hover:hover)]:group-focus-within/copyable:pointer-events-auto',
      '[@media(hover:hover)]:group-focus-within/copyable:opacity-100',
    )
  })

  it('keeps the compact table action directly beside the value', () => {
    render(
      <TableCopyableValue
        value="grantor_admin"
        label="Копировать имя аккаунта grantor_admin"
      />,
    )

    const value = screen.getByText('grantor_admin')
    expect(value.parentElement).toHaveClass('inline-flex', 'gap-1')
    expect(value).not.toHaveClass('flex-1')
    expect(screen.getByRole('button', {
      name: 'Копировать имя аккаунта grantor_admin',
    })).toHaveClass('size-6')
  })

  it('keeps at least three characters in every wrapped identifier fragment', () => {
    expect(identifierWrapSegments('ui_transition_test')).toEqual([
      'ui_',
      'transition_',
      'test',
    ])
    expect(identifierWrapSegments('ui_unmanaged_group')).toEqual([
      'ui_',
      'unmanaged_',
      'group',
    ])
    expect(identifierWrapSegments('abcdefghijklmnopq')).toEqual([
      'abcdefghijklmn',
      'opq',
    ])
  })

  it('uses safe identifier wrapping for the canonical table value', () => {
    render(
      <TableCopyableValue
        value="ui_transition_test"
        label="Копировать имя аккаунта ui_transition_test"
      />,
    )

    const value = screen.getByText('ui_transition_test')
    expect(value).toHaveClass(
      'whitespace-normal',
      '[overflow-wrap:normal]',
      '[word-break:normal]',
    )
    expect(value.querySelectorAll('wbr')).toHaveLength(2)
  })
})
