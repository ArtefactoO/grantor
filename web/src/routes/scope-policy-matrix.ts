import type { Connection, ScopePolicy, ScopeSubjectKind } from '../lib/types'

export const ENVIRONMENT_ALL = '*'
export const OPERATOR_ROLE = 'operator'

export interface ScopeMatrixSubject {
  kind: ScopeSubjectKind
  id: string
  name: string
  description: string
}

export type ScopeMatrixCellState = 'explicit' | 'inherited' | 'denied'

export interface ScopePolicyImpact {
  operation: 'create' | 'delete'
  affectedConnections: Connection[]
  exactPolicy: ScopePolicy | undefined
  wildcardPolicy: ScopePolicy | undefined
  redundantConcretePolicies: ScopePolicy[]
}

export function policiesForSubject(
  policies: readonly ScopePolicy[],
  subject: ScopeMatrixSubject,
): ScopePolicy[] {
  return policies.filter(
    (policy) => policy.subject_kind === subject.kind && policy.subject === subject.id,
  )
}

export function exactPolicyFor(
  policies: readonly ScopePolicy[],
  subject: ScopeMatrixSubject,
  environment: string,
): ScopePolicy | undefined {
  return policiesForSubject(policies, subject).find(
    (policy) => policy.environment === environment,
  )
}

/**
 * Явное правило имеет приоритет в представлении, даже если рядом существует
 * '*'. Так администратор видит и может удалить сохранённое redundant-правило,
 * не меняя эффективный доступ, который продолжает наследоваться от '*'.
 */
export function scopeCellState(
  policies: readonly ScopePolicy[],
  subject: ScopeMatrixSubject,
  environment: string,
): ScopeMatrixCellState {
  if (exactPolicyFor(policies, subject, environment) !== undefined) {
    return 'explicit'
  }
  if (
    environment !== ENVIRONMENT_ALL &&
    exactPolicyFor(policies, subject, ENVIRONMENT_ALL) !== undefined
  ) {
    return 'inherited'
  }
  return 'denied'
}

export function scopePolicyImpact(
  policies: readonly ScopePolicy[],
  subject: ScopeMatrixSubject,
  environment: string,
  connections: readonly Connection[],
): ScopePolicyImpact {
  const subjectPolicies = policiesForSubject(policies, subject)
  const exactPolicy = subjectPolicies.find((policy) => policy.environment === environment)
  const wildcardPolicy = subjectPolicies.find(
    (policy) => policy.environment === ENVIRONMENT_ALL,
  )
  const concretePolicies = subjectPolicies.filter(
    (policy) => policy.environment !== ENVIRONMENT_ALL,
  )
  const operation = exactPolicy === undefined ? 'create' : 'delete'

  const affectedConnections = connections.filter((connection) => {
    if (environment !== ENVIRONMENT_ALL) {
      if (connection.environment !== environment) return false
      // При наличии '*' добавление или удаление конкретного правила не меняет
      // эффективную видимость подключения.
      return wildcardPolicy === undefined
    }

    const hasConcreteRule = concretePolicies.some(
      (policy) => policy.environment === connection.environment,
    )
    // При добавлении и удалении '*' меняются только подключения, которые не
    // остаются покрыты конкретным правилом.
    return !hasConcreteRule
  })

  return {
    operation,
    affectedConnections,
    exactPolicy,
    wildcardPolicy,
    redundantConcretePolicies: concretePolicies,
  }
}
