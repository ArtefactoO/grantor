import { Combobox, Field } from '@project/ui'
import type { ConnectionAuthMode } from '../lib/types'

export function ConnectionAuthModeField({ value, onChange, disabled = false }: {
  value: ConnectionAuthMode
  onChange: (value: ConnectionAuthMode) => void
  disabled?: boolean
}) {
  return <Field label="Авторизация Redis">
    <Combobox label="Авторизация Redis" value={value} disabled={disabled} options={[
      { value: 'password', label: 'Пароль' }, { value: 'none', label: 'Без пароля · default' },
    ]} onValueChange={next => onChange(next === 'none' ? 'none' : 'password')} />
  </Field>
}

export function RedisNoAuthNotice() {
  return <p className="text-xs leading-relaxed text-warn" role="status">
    Redis работает без парольной авторизации. Grantor подключается как default для просмотра инвентаря.
    Создание учеток, выдача прав и ротация паролей недоступны. Настройки Redis не меняются.
  </p>
}
