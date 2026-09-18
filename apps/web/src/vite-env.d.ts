/// <reference types="vite/client" />

/**
 * 构建期注入的标识（见 vite.config.ts 的 define）。
 *
 * `dirty` = 构建时工作区有未提交改动：本地控制台是从工作区构建的，
 * 只写 commit 会让人误以为页面就是某个干净的版本。
 */
declare const __POD_BUILD__: {
  commit: string;
  dirty: boolean;
  builtAt: string;
};
