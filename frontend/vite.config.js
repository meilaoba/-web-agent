import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 后端地址（后端启动于 127.0.0.1:8000）
const proxy = {
  '/api': {
    target: 'http://127.0.0.1:8000',
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy,
  },
  // 构建后 `npm run preview` 预览时同样代理 /api，避免请求 404
  preview: {
    port: 4173,
    proxy,
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1500,
  },
})
