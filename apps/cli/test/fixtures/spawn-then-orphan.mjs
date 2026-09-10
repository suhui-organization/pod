/**
 * 测试辅助：启动一个 pod stdio 网关，把它的管道写端交给一个长命子进程持有，然后本进程退出。
 *
 * 复现真实场景：agent 被强杀（或管道写端被别的子进程继承）时网关收不到 EOF，
 * 只能靠 PPID 迁移发现 agent 已死。输出一行 JSON：{ pod, holder }。
 *
 * 退出前要等网关起来（tsx 启动约 1-2s）：网关只在「启动时父进程还在」的情况下才装 PPID 看门狗，
 * 这和真实场景一致 —— agent 先跟网关通信，之后才死掉。
 */
import { spawn } from 'node:child_process';

const [cliIndex, ...rest] = process.argv.slice(2);
const pod = spawn(process.execPath, ['--import', 'tsx', cliIndex, ...rest], { stdio: ['pipe', 'pipe', 'pipe'] });
const holder = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
  stdio: ['ignore', pod.stdin, pod.stdout],
});
process.stdout.write(JSON.stringify({ pod: pod.pid, holder: holder.pid }) + '\n');
setTimeout(() => process.exit(0), 3500);
