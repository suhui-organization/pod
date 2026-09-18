import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * 构建标识：commit + 是否有未提交改动 + 构建时间。
 *
 * 为什么要带上 dirty 标记：本地控制台是从**工作区**构建的，而工作区常常带着
 * 未提交的改动。只写 commit 会让人以为"页面 = 某个干净的版本"，
 * 实际上它可能还包含几个没进 git 的改动（`+` 就是提醒这件事）。
 */
function buildInfo(): { commit: string; dirty: boolean; builtAt: string } {
  const git = (args: string[]): string => {
    try {
      return execFileSync('git', args, { encoding: 'utf8' }).trim();
    } catch {
      return '';
    }
  };
  return {
    commit: git(['rev-parse', '--short', 'HEAD']) || 'unknown',
    dirty: git(['status', '--porcelain']).length > 0,
    builtAt: new Date().toISOString(),
  };
}

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
  // 构建期常量：界面侧栏显示"build <commit>"，一眼能看出页面是哪次构建
  define: {
    __POD_BUILD__: JSON.stringify(buildInfo()),
  },
});
