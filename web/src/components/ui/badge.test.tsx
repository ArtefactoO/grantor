import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { EngineBadge, KindBadge, PrincipalTypeChip } from './badge'

describe('EngineBadge', () => {
  it.each([
    ['mongodb', 'MongoDB'],
    ['kafka', 'Kafka'],
    ['rabbitmq', 'RabbitMQ'],
    ['redis', 'Redis'],
    ['postgres', 'PostgreSQL'],
  ])('renders %s with a valid external SVG mask URL', (engine, label) => {
    render(<EngineBadge engine={engine} />)

    const badge = screen.getByLabelText(label)
    const brand = badge.querySelector<HTMLElement>(`[data-engine-brand="${engine}"]`)
    expect(brand).not.toBeNull()
    expect(brand).toHaveClass('bg-current')
    expect(brand).toHaveStyle({ maskRepeat: 'no-repeat', maskSize: 'contain' })
    expect(brand?.style.maskImage).toMatch(/^url\(".+\.svg(?:\?.*)?"\)$/)
    expect(brand?.style.maskImage).not.toContain('data:')
    expect(brand?.style.webkitMaskImage).toBe(brand?.style.maskImage)
  })

  it('keeps an accessible neutral fallback for an unknown engine', () => {
    render(<EngineBadge engine="newdb" />)

    const badge = screen.getByLabelText('newdb')
    expect(badge.querySelector('[data-engine-brand]')).toBeNull()
    expect(badge.querySelector('svg')).not.toBeNull()
  })
})

describe('principal type visuals', () => {
  it.each([
    ['human', 'Human'],
    ['service', 'Service'],
    ['group', 'Group'],
  ])('renders a shared %s icon inside the type chip', (type, label) => {
    render(<PrincipalTypeChip type={type} />)

    expect(screen.getByTitle(label).querySelector(`[data-principal-type="${type}"]`)).not.toBeNull()
  })

  it('uses a linked service principal icon instead of a generic login icon', () => {
    render(<KindBadge kind="login" principalType="service" />)

    expect(screen.getByTitle('Login · Service').querySelector('[data-principal-type="service"]')).not.toBeNull()
  })

  it('keeps kind icon and label on the same line', () => {
    render(<KindBadge kind="group" />)

    expect(screen.getByText('Group')).toHaveClass('whitespace-nowrap')
  })
})
