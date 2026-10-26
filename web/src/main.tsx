// Точка входа UI grantor: React Query + TanStack Router + MotionConfig
// (уважает prefers-reduced-motion) поверх AuthProvider.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { MotionConfig } from 'motion/react'
import './styles/base.css'
import { AuthProvider } from './auth/AuthProvider'
import { ToastProvider } from '@project/ui'
import { router } from './routes/router'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5_000,
      refetchOnWindowFocus: true,
    },
  },
})

const rootElement = document.getElementById('root')
if (rootElement === null) {
  throw new Error('index.html не содержит #root')
}

createRoot(rootElement).render(
  <StrictMode>
    <MotionConfig reducedMotion="user">
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastProvider>
            <RouterProvider router={router} />
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MotionConfig>
  </StrictMode>,
)
