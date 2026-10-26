import { resourceKindLabel } from '../../lib/ui-copy'
import { TagBadge } from './badge'

export function ResourceTypeChip({ kind }: { kind: string }) {
  return <TagBadge title={`Тип ресурса: ${resourceKindLabel(kind)}`}>{resourceKindLabel(kind)}</TagBadge>
}
