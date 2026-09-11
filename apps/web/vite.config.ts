import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * 本地控制台前端（`pod ui` 的静态产物）。
 *
 * - dev：`pnpm dev`，`/api/*` 反代到 `pod ui` 的本地服务（127.0.0.1:8787）；
 * - build：产物交给 CLI 托管，服务端同源提供 /api，无需反代。
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // 数据契约直接读 @podsec/console 的类型源文件：dev / typecheck 都不依赖包先构建
      '@podsec/console/types': fileURLToPath(
        new URL('../../packages/console/src/types.ts', import.meta.url),
      ),
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8787', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
});
