import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { EnvironmentPickerDialog } from './environment-picker-dialog'

function open(environments: string[]) {
  return render(
    <EnvironmentPickerDialog
      open
      title="Получить учётные данные"
      description="Будет создана одноразовая ссылка."
      confirmLabel="Получить"
      environments={environments}
      pending={false}
      onConfirm={vi.fn()}
      onClose={vi.fn()}
    />,
  )
}

describe('выбор окружения', () => {
  // Реестр окружений и форма подключения показывают имя как его завели;
  // апперкейс здесь делал «PROD» и «prod» похожими на разные сущности.
  it('показывает имена окружений как есть', async () => {
    open(['prod', 'test'])

    await userEvent.click(screen.getByRole('combobox', { name: 'Окружение' }))

    expect(await screen.findByText('prod')).toBeInTheDocument()
    expect(screen.getByText('test')).toBeInTheDocument()
    expect(screen.queryByText('PROD')).not.toBeInTheDocument()
    expect(screen.queryByText('TEST')).not.toBeInTheDocument()
  })

  it('выбирает единственное окружение сразу', () => {
    open(['prod'])
    expect(screen.getByRole('combobox', { name: 'Окружение' })).toHaveTextContent('prod')
  })
})
