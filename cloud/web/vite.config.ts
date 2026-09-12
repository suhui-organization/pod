import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    // 本地联调会把 dev server 暴露到隧道域名（ngrok / cloudflared）。
    // Vite 默认只接受 localhost，Host 是隧道域名时会直接 403，
    // 表现为"隧道能连通但页面打不开"。只影响 dev；生产走 nginx 不看 Host。
    allowedHosts: ['.ngrok-free.dev', '.ngrok.app', '.trycloudflare.com', 'localhost'],
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    cssCodeSplit: false,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
      },
    },
  },
})
