import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Listen on all interfaces so teammates can open the dashboard at
    // http://<server-ip>:5173 during a LAN demo.
    host: true,
    port: 5173,
    // Proxy API + WebSocket through the Vite origin so the UI works whether
    // opened via localhost or a LAN IP (avoids hardcoding 127.0.0.1:8000).
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
      },
    },
  },
})
