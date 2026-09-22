import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import path from "node:path"

// Vite config — https://vitejs.dev/config/
const host = process.env.HOST || "localhost"
const port = parseInt(process.env.PORT || "8443")

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
    dedupe: ["react", "react-dom"],
  },
  server: {
    host,
    port,
    strictPort: true,
    // 개발 중 /api 요청은 Flask 백엔드로 전달한다.
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
    watch: {
      ignored: ["**/.browser-check/**", "**/artifacts/**"],
    },
  },
  preview: {
    host,
    port,
    strictPort: true,
  },
})
