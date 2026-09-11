import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 30000,
    hookTimeout: 30000,
    // CLI 测试会真的 spawn `pod` 子进程、抢端口、共用 ~/.pod 与临时目录，
    // 并行跑同一台机器上会互相踩（本地实测并行 9 个失败、串行全绿，
    // 且串行反而更快：76s vs 97s）。这里按文件串行，换确定性。
    fileParallelism: false,
    // 本地 worktree 是仓库的完整副本（.worktrees/ 已 gitignore），
    // 不排除的话 vitest 会把它当第二份测试跑，既翻倍又用旧代码报假失败。
    exclude: ['**/node_modules/**', '**/dist/**', '**/.worktrees/**'],
  },
});
