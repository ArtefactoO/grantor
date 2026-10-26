import type { AccessExportSection } from '../lib/types'

export const STATE_SECTIONS: readonly AccessExportSection[] = [
  'managed',
  'unmanaged',
  'roles',
  'accounts',
]

export type AccessDocumentKind = 'manifest' | 'snapshot'
export type StateDocumentFormat = 'json' | 'yaml'

export function isManagedManifest(sections: ReadonlySet<AccessExportSection>): boolean {
  return sections.size === 1 && sections.has('managed')
}

export function detectStateDocumentFormat(
  text: string,
  fileName: string | null,
): StateDocumentFormat {
  const lower = fileName?.toLowerCase() ?? ''
  if (lower.endsWith('.json')) return 'json'
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml'
  const first = text.trimStart().charAt(0)
  return first === '{' || first === '[' ? 'json' : 'yaml'
}

interface DetectedDocument {
  kind: AccessDocumentKind
  sections: Set<AccessExportSection>
}

function objectDocument(value: unknown): DetectedDocument | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const object = value as Record<string, unknown>
  if (object.kind === 'access_snapshot') {
    const sections = STATE_SECTIONS.filter((section) => section in object)
    return {
      kind: 'snapshot',
      sections: new Set(sections.length > 0 ? sections : ['managed']),
    }
  }
  if (typeof object.version === 'string' && Array.isArray(object.entries)) {
    return { kind: 'manifest', sections: new Set(['managed']) }
  }
  return null
}

/**
 * Определяется только верхнеуровневый вид документа. Полную YAML/JSON-схему
 * авторитетно валидирует backend plan — браузер не поддерживает вторую схему.
 */
export function detectStateDocument(
  text: string,
  fileName: string | null,
): DetectedDocument | null {
  if (detectStateDocumentFormat(text, fileName) === 'json') {
    try {
      return objectDocument(JSON.parse(text) as unknown)
    } catch {
      return null
    }
  }

  const topLevel = new Set<string>()
  for (const line of text.split(/\r?\n/)) {
    if (/^\s/.test(line)) continue
    const match = line.match(/^([a-z_]+)\s*:/i)
    if (match?.[1] !== undefined) topLevel.add(match[1])
  }
  if (/^kind\s*:\s*access_snapshot\s*(?:#.*)?$/im.test(text)) {
    const sections = STATE_SECTIONS.filter((section) => topLevel.has(section))
    return {
      kind: 'snapshot',
      sections: new Set(sections.length > 0 ? sections : ['managed']),
    }
  }
  if (/^version\s*:\s*[^\s#]+/im.test(text) && topLevel.has('entries')) {
    return { kind: 'manifest', sections: new Set(['managed']) }
  }
  return null
}

export function stateExportPath(
  connectionId: string,
  sections: ReadonlySet<AccessExportSection>,
  format: StateDocumentFormat = 'yaml',
): string {
  const params = new URLSearchParams({
    connection: connectionId,
    sections: STATE_SECTIONS.filter((section) => sections.has(section)).join(','),
    format,
  })
  return `/api/v1/access/export?${params.toString()}`
}
