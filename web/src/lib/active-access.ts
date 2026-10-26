import type { Binding } from './types'

/**
 * Право можно показывать как действующее только когда оно по-прежнему
 * требуется (managed present либо unmanaged) и discovery видит его в target.
 * desired=absent означает начатый/завершённый отзыв, observed=absent|unknown
 * не доказывает фактический доступ.
 */
export function isActiveAccessBinding(binding: Binding): boolean {
  return (
    binding.observed_state === 'present' &&
    (binding.desired_state === null || binding.desired_state === 'present')
  )
}

export function activeAccessBindings(bindings: readonly Binding[]): Binding[] {
  return bindings.filter(isActiveAccessBinding)
}

/**
 * Зеркало internal/core/inventory.BindingNeedsRepair — менять синхронно.
 * Достоверно известная поломка затребованного права: применение упало,
 * снято снаружи либо выдано, но не действует. observed=unknown без failed
 * поломкой не считается: свежий грант ещё не наблюдался.
 */
export function bindingNeedsRepair(binding: Binding): boolean {
  if (binding.desired_state !== 'present') return false
  if (binding.status === 'failed') return true
  if (
    (binding.assignment_key ?? '') !== '' &&
    binding.observed_state === 'present' &&
    binding.observed_permission_definition_id !== binding.permission_definition_id
  ) return true
  switch (binding.observed_state) {
    case 'absent':
      return true
    case 'present':
      return !binding.observed_effective
    default:
      return false
  }
}

/**
 * «Роль уже назначена» — тот же предикат, по которому API отвечает 409 на
 * повторную выдачу. Диалоги обязаны использовать его, а не свои варианты:
 * расхождение либо блокирует починку навсегда, либо ведёт клик в 409.
 */
export function isAssignedManagedBinding(binding: Binding): boolean {
  return binding.desired_state === 'present' && !bindingNeedsRepair(binding)
}
