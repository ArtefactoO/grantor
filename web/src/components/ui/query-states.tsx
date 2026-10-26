// Свёртка триады loading/error/empty запроса react-query в один блок:
// ошибка → ErrorState с повтором, загрузка → скелетон, пусто → переданный
// empty, иначе — children(data).
import type { ReactNode } from 'react'
import { errorMessage } from '../../lib/errorMessage'
import { ErrorState, LoadingSkeleton, RowSkeleton } from '@project/ui'

/** Минимальный контракт результата useQuery, нужный триаде состояний. */
export interface QueryLike<T> {
  isError: boolean
  isPending: boolean
  error: unknown
  data: T | undefined
  refetch: () => Promise<unknown>
}

export interface QueryStatesProps<T> {
  query: QueryLike<T>
  /** Разметка пустого состояния; показывается, когда isEmpty(data) истинно. */
  empty?: ReactNode
  /**
   * Предикат пустоты; по умолчанию — пустой массив. Для не-массивных данных
   * (envelope с полем-списком) передаётся явно.
   */
  isEmpty?: (data: T) => boolean
  /** Заглушка загрузки; по умолчанию — список строк той же формы. */
  skeleton?: ReactNode
  children: (data: T) => ReactNode
}

const defaultIsEmpty = (data: unknown): boolean =>
  Array.isArray(data) && data.length === 0

export function QueryStates<T>({ query, empty, isEmpty, skeleton, children }: QueryStatesProps<T>) {
  if (query.isError) {
    return (
      <ErrorState
        message={errorMessage(query.error)}
        onRetry={() => {
          void query.refetch()
        }}
      />
    )
  }
  if (query.isPending) {
    // Скелетон вместо спиннера: экран не прыгает с пустого на полный, и
    // ожидание ощущается короче при том же времени ответа.
    return <LoadingSkeleton>{skeleton ?? <RowSkeleton />}</LoadingSkeleton>
  }
  // Вне isPending/isError react-query гарантирует наличие данных.
  const data = query.data as T
  if (empty !== undefined && (isEmpty ?? defaultIsEmpty)(data)) {
    return <>{empty}</>
  }
  return <>{children(data)}</>
}
