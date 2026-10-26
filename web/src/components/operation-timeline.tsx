// Лента этапов операции: где она была и сколько там простояла.
import { buildOperationTimeline, formatStepDuration } from '../lib/operation-timeline'
import type { TimelineStep } from '../lib/operation-timeline'
import { formatDateTime } from '../lib/time'
import type { Operation } from '../lib/types'
import { Card } from '@project/ui'

const DOT_TONES: Record<TimelineStep['state'], string> = {
  done: 'bg-ok',
  active: 'bg-warn',
  failed: 'bg-danger',
  pending: 'bg-line-strong',
}

export function OperationTimeline({ operation }: { operation: Operation }) {
  const steps = buildOperationTimeline(operation)
  return (
    <Card className="mt-5 p-3">
      <h3 className="text-xs font-semibold text-faint">Ход операции</h3>
      <ol className="mt-3 space-y-3">
        {steps.map((step, index) => {
          const duration = formatStepDuration(step.durationMs)
          return (
            <li key={step.key} className="relative flex gap-3 pl-1">
              {index < steps.length - 1 && (
                <span aria-hidden="true" className="absolute left-[7px] top-4 h-full w-px bg-line" />
              )}
              <span
                aria-hidden="true"
                className={`relative mt-1 size-3 shrink-0 rounded-full ${DOT_TONES[step.state]} ${step.state === 'active' ? 'animate-pulse motion-reduce:animate-none' : ''}`}
              />
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
                  <span className={`text-sm ${step.state === 'pending' ? 'text-faint' : 'text-text'}`}>{step.label}</span>
                  {step.at !== null && (
                    <time dateTime={step.at} className="text-xs tabular-nums text-muted">{formatDateTime(step.at)}</time>
                  )}
                </span>
                {duration !== null && (
                  <span className="mt-0.5 block text-xs text-faint">
                    {step.state === 'active' ? 'идёт ' : ''}{duration}
                  </span>
                )}
              </span>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
