/**
 * Feedback acknowledges state without moving controls or delaying an action.
 * Geometry is applied immediately; only an active process may repeat motion.
 */
export const MOTION_DURATION = {
  fast: 0.09,
  state: 0.13,
  feedback: 0.13,
  panel: 0.15,
  layout: 0.15,
} as const

export const MOTION_EASE = {
  feedback: [0.2, 0.8, 0.2, 1],
  entrance: [0.16, 1, 0.3, 1],
  exit: [0.4, 0, 1, 1],
} as const

export const MOTION_TRANSITION = {
  overlay: { duration: MOTION_DURATION.state, ease: MOTION_EASE.feedback },
  dialog: { duration: MOTION_DURATION.feedback, ease: MOTION_EASE.entrance },
  panel: { duration: MOTION_DURATION.panel, ease: MOTION_EASE.entrance },
  feedback: { duration: MOTION_DURATION.feedback, ease: MOTION_EASE.feedback },
  layout: { duration: MOTION_DURATION.layout, ease: MOTION_EASE.feedback },
  operationProgress: {
    duration: 1.25,
    ease: 'easeInOut',
    repeat: Number.POSITIVE_INFINITY,
  },
} as const

/** Reduced motion keeps final state and geometry visible on the first frame. */
export function motionTransition(
  kind: Exclude<keyof typeof MOTION_TRANSITION, 'operationProgress'>,
  reducedMotion: boolean | null,
) {
  const transition = MOTION_TRANSITION[kind]
  return reducedMotion ? { ...transition, duration: 0 } : transition
}

export const MOTION_VARIANTS = {
  overlay: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
  dialog: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
  drawer: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
  sidePanel: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
  notice: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
  statusIcon: {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 },
  },
} as const
