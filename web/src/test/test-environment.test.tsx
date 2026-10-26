import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

describe('frontend test environment', () => {
  it('renders React into jsdom with Testing Library matchers', () => {
    render(<button type="button">Grant access</button>)

    expect(screen.getByRole('button', { name: 'Grant access' })).toBeInTheDocument()
  })
})
