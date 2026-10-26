import { describe, expect, it } from 'vitest'
import {
  STATE_SECTIONS,
  detectStateDocument,
  detectStateDocumentFormat,
  isManagedManifest,
  stateExportPath,
} from './connection-state'

describe('connection state document contract', () => {
  it('treats only Managed as an applicable manifest', () => {
    expect(isManagedManifest(new Set(['managed']))).toBe(true)
    expect(isManagedManifest(new Set(['managed', 'roles']))).toBe(false)
    expect(isManagedManifest(new Set())).toBe(false)
  })

  it('detects manifest and snapshot without duplicating backend validation', () => {
    expect(detectStateDocument('version: v1\nentries: []\n', 'state.yaml')).toEqual({
      kind: 'manifest',
      sections: new Set(['managed']),
    })
    expect(detectStateDocument(
      'kind: access_snapshot\nmanaged: []\nroles: []\n',
      'state.yaml',
    )).toEqual({ kind: 'snapshot', sections: new Set(['managed', 'roles']) })
    expect(detectStateDocument('entries: []\n', 'unknown.yaml')).toBeNull()
    expect(detectStateDocumentFormat('{"version":"v1","entries":[]}', null)).toBe('json')
  })

  it('keeps export section order and connection scope stable', () => {
    expect(STATE_SECTIONS).toEqual(['managed', 'unmanaged', 'roles', 'accounts'])
    expect(stateExportPath('connection id', new Set(['accounts', 'managed']))).toBe(
      '/api/v1/access/export?connection=connection+id&sections=managed%2Caccounts&format=yaml',
    )
  })
})
