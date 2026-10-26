// Кнопка в стиле принятой концепции: медь — только действия.
// Стилизация исключительно токенами (см. src/styles/tokens.css).
import { forwardRef } from 'react'
import type { ButtonHTMLAttributes } from 'react'
import { cn } from './cn'

export type ButtonVariant = 'primary' | 'outline' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
}

const BASE_CLASSES =
  'grantor-touch-target ui-control-feedback ui-button inline-flex select-none items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:pointer-events-none disabled:opacity-50'

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-ink hover:bg-accent-hover',
  outline: 'border border-line bg-transparent text-text hover:bg-panel2',
  ghost: 'text-muted hover:bg-panel2 hover:text-text',
  danger: 'border border-danger/40 bg-danger-soft text-danger hover:bg-danger/25',
}

const SIZE_CLASSES: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-xs',
  md: 'h-9 px-3.5 text-sm',
}

/** Shared action styling for native buttons and navigation links. */
export function buttonClassName(
  variant: ButtonVariant = 'primary',
  size: ButtonSize = 'md',
  className?: string,
): string {
  return cn(BASE_CLASSES, VARIANT_CLASSES[variant], SIZE_CLASSES[size], className)
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', className, type, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      // По умолчанию type="button", чтобы кнопки в формах не сабмитили их
      // случайно.
      type={type ?? 'button'}
      className={buttonClassName(variant, size, className)}
      {...rest}
    />
  )
})
