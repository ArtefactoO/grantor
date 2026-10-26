// Vitest runs in Node; the production bundle never includes this source guard.
// @ts-expect-error web tsconfig intentionally excludes global Node types.
import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const source = (path: string) => readFileSync(`src/${path}`, 'utf8')

describe('connection-owned inventory architecture', () => {
  it('does not reintroduce removed global page modules', () => {
    for (const file of [
      'routes/access.tsx',
      'routes/resources.tsx',
      'routes/manifest.tsx',
      'routes/manifest-state.ts',
    ]) {
      expect(existsSync(`src/${file}`), file).toBe(false)
    }

    const sidebar = source('components/layout/Sidebar.tsx')
    expect(sidebar).not.toContain("to: '/resources'")
    expect(sidebar).not.toContain("to: '/access'")
    expect(sidebar).not.toContain("to: '/manifest'")
  })

  it('keeps the full directory on Overview and State as a connection action', () => {
    const router = source('routes/router.tsx')
    const overview = source('routes/overview.tsx')
    const sidebar = source('components/layout/Sidebar.tsx')
    const appShell = source('components/layout/AppShell.tsx')
    const connection = source('routes/connection-detail.tsx')

    expect(router).not.toContain("import('./connections')")
    expect(router).toContain("throw redirect({ to: '/overview' })")
    expect(overview).toContain('<ConnectionDirectory')
    expect(sidebar).not.toContain("label: 'Подключения'")
    expect(sidebar).not.toContain('<span>Подключение</span>')
    expect(sidebar).toContain('activeConnectionName !== undefined')
    expect(connection).not.toContain("{ key: 'state', label: 'Состояние'")
    expect(connection).not.toContain('<ConnectionStateTool connection={connection} />')
    expect(connection).toContain('label="Состояние подключения"')
    expect(connection).toContain("{ key: 'hba', label: 'pg_hba', zone: 'sync' }")
    expect(connection).toContain('<ConnectionHBASection data={hbaQuery.data} />')
    const statePage = source('routes/connection-state-page.tsx')
    expect(statePage).not.toContain('ConnectionHBASection')
    expect(router).toContain("path: '/connections/$connectionId/state'")
    expect(router).toContain('defaultPendingMs: 180')
    expect(router).toContain("defaultPreload: 'intent'")
    expect(appShell).toContain('[scrollbar-gutter:stable]')
    expect(sidebar).not.toContain('active:scale-[0.98]')
  })

  it('keeps role lists free of route-local security badges and implementation terms', () => {
    const connection = source('routes/connection-detail.tsx')
    const grantAccount = source('routes/connection-account-dialogs.tsx')
    const grantPrincipal = source('routes/principal-access-drawer.tsx')
    const visibleSources = [connection, grantAccount, grantPrincipal].join('\n')

    expect(visibleSources).not.toContain('<TableHead>Assignable</TableHead>')
    expect(visibleSources).not.toContain('<TableHead>Dangerous</TableHead>')
    expect(visibleSources).not.toContain('>Dangerous</StatusChip>')
    expect(visibleSources).not.toContain('assignable-роли')
    expect(grantPrincipal).toContain('<ElevatedAccessDot />')
  })
})
