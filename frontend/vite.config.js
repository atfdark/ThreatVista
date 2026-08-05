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
  },
})
