// Поля форм: Input, Textarea и обёртка Field (подпись + контрол + hint).
import { forwardRef } from 'react'
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react'
import { Info } from './icons'
import { cn } from './cn'
import { Tooltip } from './tooltip'

const CONTROL_CLASSES =
  'grantor-touch-target w-full rounded-md border border-line bg-panel2 px-3 text-sm text-text placeholder:text-faint focus:border-accent focus:outline-none disabled:opacity-50'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return <input ref={ref} className={cn('h-9', CONTROL_CLASSES, className)} {...rest} />
  },
)

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...rest }, ref) {
  return (
    <textarea
      ref={ref}
      className={cn('min-h-20 py-2 leading-relaxed', CONTROL_CLASSES, className)}
      {...rest}
    />
  )
})

export interface FieldProps {
  label: string
  hint?: string
  tooltip?: ReactNode
  children: ReactNode
  className?: string
  htmlFor?: string
}

/** Подпись над контролом и необязательный hint под ним. */
export function Field({ label, hint, tooltip, children, className, htmlFor }: FieldProps) {
  return (
    <label className={cn('block', className)} htmlFor={htmlFor}>
      <span className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-muted">
        {label}
        {tooltip !== undefined && (
          <Tooltip
            content={tooltip}
            disabledTarget
            targetLabel={`Подсказка: ${label}`}
          >
            <Info className="size-3.5 text-faint" aria-hidden="true" />
          </Tooltip>
        )}
      </span>
      {children}
      {hint !== undefined && (
        <span className="mt-1 block text-xs text-faint">{hint}</span>
      )}
    </label>
  )
}
