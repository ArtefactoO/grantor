import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import { qk } from './queryKeys'

interface FavoriteConnections { connection_ids: string[] }

export function useConnectionFavorites() {
  const client = useQueryClient()
  const query = useQuery({
    queryKey: qk.favoriteConnections(),
    queryFn: ({ signal }) => api<FavoriteConnections>('/api/v1/me/favorite-connections', { signal }),
    staleTime: 60_000,
  })
  const mutation = useMutation({
    mutationFn: ({ id, favorite }: { id: string; favorite: boolean }) =>
      api<void>(`/api/v1/me/favorite-connections/${encodeURIComponent(id)}`, { method: favorite ? 'PUT' : 'DELETE' }),
    onSuccess: (_, { id, favorite }) => {
      client.setQueryData<FavoriteConnections>(qk.favoriteConnections(), previous => {
        const ids = new Set(previous?.connection_ids ?? [])
        if (favorite) ids.add(id)
        else ids.delete(id)
        return { connection_ids: [...ids] }
      })
      void client.invalidateQueries({ queryKey: qk.favoriteConnections() })
    },
  })
  const ids = useMemo(() => new Set(query.data?.connection_ids ?? []), [query.data])
  return { query, ids, mutation }
}
