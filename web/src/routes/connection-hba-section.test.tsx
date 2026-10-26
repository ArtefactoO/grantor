import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ConnectionHBASection } from './connection-hba-section'
import type { HBAResponse, HBARule } from './connection-hba-section'

function rule(overrides: Partial<HBARule> = {}): HBARule {
  return {
    number: 1,
    type: 'host',
    databases: ['all'],
    users: ['all'],
    address: '10.0.0.0',
    netmask: '8',
    auth_method: 'scram-sha-256',
    options: [],
    error: '',
    ...overrides,
  }
}

function data(overrides: Partial<HBAResponse> = {}): HBAResponse {
  return {
    supported: true,
    customized: true,
    truncated: false,
    rules: [rule()],
    uncovered_accounts: [],
    ...overrides,
  }
}

describe('ConnectionHBASection', () => {
  it('lists the rules of the connection', () => {
    render(<ConnectionHBASection data={data()} />)

    expect(screen.getByText('scram-sha-256')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.0/8')).toBeInTheDocument()
  })

  // Учётка без правила не попадёт в кластер даже с выданными правами — это
  // и есть повод показать предупреждение.
  it('warns about accounts without a matching rule', () => {
    render(<ConnectionHBASection data={data({
      rules: [rule({ users: ['+app_read'] })],
      uncovered_accounts: ['orphan_user'],
    })} />)

    expect(screen.getByText(/orphan_user/)).toBeInTheDocument()
    expect(screen.getByText(/вход\s+может быть невозможен/i)).toBeInTheDocument()
  })

  it('stays quiet when every account is covered', () => {
    render(<ConnectionHBASection data={data()} />)

    expect(screen.queryByText(/может быть невозможен/)).not.toBeInTheDocument()
  })

  // Сломанная строка pg_hba сервером не применяется — это сигнал, а не повод
  // её прятать.
  it('marks a broken rule instead of hiding it', () => {
    render(<ConnectionHBASection data={data({
      rules: [rule({ error: 'invalid connection type' })],
    })} />)

    expect(screen.getByText('Ошибка')).toBeInTheDocument()
  })

  // Отсутствие доступа к view — не ошибка подключения: объясняем, чего не
  // хватает, вместо пустой таблицы.
  it('explains what is missing when the rules cannot be read', () => {
    render(<ConnectionHBASection data={data({
      supported: false,
      customized: false,
      rules: [],
    })} />)

    expect(screen.getByText(/pg_hba_file_rules/)).toBeInTheDocument()
    expect(screen.getByText(/PostgreSQL 15 или новее/)).toBeInTheDocument()
  })
})
