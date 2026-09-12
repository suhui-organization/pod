import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // CLI 测试会真的 spawn `pod` 子进程（tsx 启动约 0.5-1s，并发时更慢）。
    // 30s 在负载高的机器上会把"慢"误报成"错"（实测过一次：同一份代码
    // 本轮 167s/1 failed，紧接着 44s/全绿）。给足余量，宁可慢也不要假失败。
    testTimeout: 60000,
    hookTimeout: 60000,
    // CLI 测试会真的 spawn `pod` 子进程、抢端口、共用 ~/.pod 与临时目录，
    // 并行跑同一台机器上会互相踩（本地实测并行 9 个失败、串行全绿，
    // 且串行反而更快：76s vs 97s）。这里按文件串行，换确定性。
    fileParallelism: false,
    // 本地 worktree 是仓库的完整副本（.worktrees/ 已 gitignore），
    // 不排除的话 vitest 会把它当第二份测试跑，既翻倍又用旧代码报假失败。
    exclude: ['**/node_modules/**', '**/dist/**', '**/.worktrees/**'],
  },
});
