// @ts-expect-error Node APIs are used only by Vitest, not by the browser bundle.
import { readFileSync, readdirSync } from 'node:fs'
// @ts-expect-error Node APIs are used only by Vitest, not by the browser bundle.
import { resolve, dirname, sep } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const packageRoot = resolve('packages/project-ui')
const sourceRoot = resolve(packageRoot, 'src')
const manifest = JSON.parse(readFileSync(resolve(packageRoot, 'package.json'), 'utf8')) as {
  exports: Record<string, string>
  dependencies: Record<string, string>
  peerDependencies: Record<string, string>
}

function importedSources(file: string): string[] {
  const syntax = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest)
  const sources: string[] = []
  const visit = (node: ts.Node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)) {
      sources.push(node.moduleSpecifier.text)
    }
    ts.forEachChild(node, visit)
  }
  visit(syntax)
  return sources
}

describe('reusable UI package boundary', () => {
  it('keeps public exports inside the package and resolves each exported entry', () => {
    for (const target of Object.values(manifest.exports)) {
      const file = resolve(packageRoot, target)
      expect(file.startsWith(`${sourceRoot}${sep}`)).toBe(true)
      expect(readFileSync(file, 'utf8').length).toBeGreaterThan(0)
    }
  })

  it('does not import application code or undeclared runtime dependencies', () => {
    const dependencies = new Set([
      ...Object.keys(manifest.dependencies),
      ...Object.keys(manifest.peerDependencies),
    ])
    const files = (readdirSync(sourceRoot, { recursive: true }) as string[])
      .filter((name) => /\.tsx?$/.test(name) && !name.includes('.test.'))
    for (const name of files) {
      const file = resolve(sourceRoot, name)
      for (const source of importedSources(file)) {
        if (source.startsWith('.')) {
          expect(resolve(dirname(file), source).startsWith(`${sourceRoot}${sep}`),
            `${name}: ${source} escapes the UI package`).toBe(true)
        } else {
          const dependency = source.startsWith('@')
            ? source.split('/').slice(0, 2).join('/')
            : source.split('/')[0]
          expect(dependencies.has(dependency), `${name}: undeclared dependency ${source}`).toBe(true)
        }
      }
    }
  })
})
