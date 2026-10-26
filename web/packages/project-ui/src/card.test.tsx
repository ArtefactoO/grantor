import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Card, StatTile } from './card'

describe('shared stable surfaces', () => {
  it('distinguishes an unavailable metric from a measured zero', () => {
    const { rerender } = render(<StatTile label="Подключения" value={null} />)
    expect(screen.getByLabelText('Нет актуальных данных')).toBeVisible()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
    rerender(<StatTile label="Подключения" value={0} />)
    expect(screen.getByText('0')).toBeVisible()
    expect(screen.queryByLabelText('Нет актуальных данных')).not.toBeInTheDocument()
  })

  it('does not read layout or mutate lighting on pointer movement', () => {
    render(<Card>Состояние</Card>)

    const card = screen.getByText('Состояние')
    const measure = vi.spyOn(card, 'getBoundingClientRect')
    const updateStyle = vi.spyOn(card.style, 'setProperty')

    fireEvent.pointerMove(card, { clientX: 180, clientY: 120 })

    expect(measure).not.toHaveBeenCalled()
    expect(updateStyle).not.toHaveBeenCalled()
  })

  it('updates metric values immediately without moving the tile', () => {
    const { rerender } = render(<StatTile label="Подключения" value={2} interactive />)
    const tile = screen.getByText('Подключения').parentElement!
    const measure = vi.spyOn(tile, 'getBoundingClientRect')
    fireEvent.pointerMove(tile, { clientX: 180, clientY: 120 })
    expect(measure).not.toHaveBeenCalled()
    expect(screen.getByText('2')).toBeVisible()

    rerender(<StatTile label="Подключения" value={10} interactive />)
    expect(screen.getByText('10')).toBeVisible()
    expect(screen.queryByText('2')).not.toBeInTheDocument()
  })
})
