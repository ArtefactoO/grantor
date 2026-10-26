import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev-сервер проксирует API и auth на api, опубликованный docker compose
// на host-порту 58082 (в контейнерном варианте то же самое делает nginx).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        // Route chunks не должны каждый раз дублировать тяжёлое runtime-ядро;
        // стабильные vendor chunks также удерживают entry заметно ниже 500 kB.
        manualChunks: {
          'tanstack-vendor': ['@tanstack/react-query', '@tanstack/react-router'],
          'motion-vendor': ['motion'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:58082',
      '/auth': 'http://localhost:58082',
      '/health': 'http://localhost:58082',
    },
  },
})
