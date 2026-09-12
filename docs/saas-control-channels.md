# SaaS ↔ 机器：两条控制通道

> 2026-09-12。本文写清 web 与用户机器之间**能互相做什么**、以及每条通道的安全边界。
> 本地工具与 web 是同一产品的两种形态，不是两套东西。

---

## 0. 全景

```
                        ┌─────────────── Pod Cloud (web) ───────────────┐
                        │  资产 / 告警 / 控制平面 / 策略 / 规则包 / 加固报告  │
                        └───┬───────────────────────────────────────┬───┘
                            │                                       │
        ① 上行（机器 → web）  │                                       │  ② 下行（web → 机器）
        pod sync / harden    │                                       │  期望状态，机器主动拉
                            ▼                                       ▼
                        ┌───────────── 用户机器（pod CLI + 网关）─────────────┐
                        │  audit 哈希链 · policy 执法 · quarantine · posture  │
                        └────────────────────────────────────────────────────┘
```

**为什么下行是"机器主动拉"而不是 web 推送**：机器通常在 NAT 后面、经常离线，
服务端连不上它。所以下行通道一律是**期望状态**（desired state），不是一次性命令——
命令在机器离线时就永远丢了，期望状态是幂等的：离线一周的机器上线后一次拉取即对齐。

| 通道 | 载体 | 鉴权 | 状态 |
|------|------|------|------|
| 审计事件上行 | `pod sync` | `X-Sync-Token` | 已有 |
| 控制平面事件上行 | `pod sync` | `X-Sync-Token` | 已有 |
| 加固报告上行 | `pod harden --upload` | `X-Sync-Token` | 本次 |
| 策略下发 | `pod pull-policy` | `X-Sync-Token` | 已有 |
| 规则包下发 | `pod rules pull --from-cloud` | `X-Sync-Token` | 上一批 |
| **熔断下发** | `pod sync`（内嵌收敛） | `X-Sync-Token` | 本次 |

一份 token 打通全部通道：接入脚本只需要发一次凭证。

---

## 1. 熔断下发（web → 机器）

### 用法

```bash
# 机器侧（通常已在定时任务里）
pod sync
```

web 上点「熔断」→ 填原因 → 机器下次 `pod sync` 时拉到并落盘 → **网关随即拒绝该 agent 的全部调用**
（`checkQuarantine` 在热路径上，无需重启网关）。

### 三条安全规则（各有测试）

1. **拉取失败什么都不做。** 断网不能等于"解除熔断"——否则攻击者只要切断机器的出网，
   就能解除云端下的熔断。失败时本地熔断纹丝不动。
2. **不接管人工条目。** 机器上已经有人（`pod quarantine add`）下过熔断时，云端不说
   "这条是我的"，因此后续解除也不会顺手删掉它。
3. **只解除自己下的。** 云端解除时只清理 `by=cloud` 的条目；人工下的（`by=cli-user`）
   留在机器上，要解除只能到机器上执行。

一句话：**云端只能撤销自己的处置，不能撤销人在机器上做的处置。**

### 局限（不假装实时）

- 生效延迟 = `pod sync` 的调度间隔。没配定时任务就等于没有这条通道；
- 机器离线时它保持当前状态，云端改不动它；
- 粒度是"本地 agent 名"（`pod serve --agent` 的那个名字），不是工具级。

---

## 2. 加固报告上传（机器 → web）

### 用法

```bash
pod harden --upload          # 生成交付物并上传
pod harden                   # 只生成，不出网
```

web「加固报告」页看列表与正文，可下载 `.md`。

### 传什么、不传什么

| 产物 | 是否上传 | 为什么 |
|------|----------|--------|
| `report.md` | ✅ | 客户本来就要给人看的交付物 |
| `findings.json` | ✅ | 机器可读发现，密钥只留掩码 |
| `manifest.json` | ❌ | 哈希清单是给本地校验用的 |
| `evidence.json` | ❌ | **原始审计链**——"本地优先"承诺的核心 |

上传是**显式动作**：报告里有路径、工具名等业务信息，不能因为"配了云"就默认传上去。
CLI 每次都会打印"传了什么、没传什么"，承诺要能被验证而不是靠信任。

---

## 3. 代码落点

| 关注点 | 位置 |
|--------|------|
| 熔断期望状态（服务端） | `cloud/server/app/routers/agents.py`、`routers/sync.py` |
| 熔断收敛（机器侧） | `apps/cli/src/sync.ts` 的 `syncQuarantine()` |
| 熔断本地语义（复用） | `apps/cli/src/control-plane.ts` 的 `quarantineAdd/Remove` |
| 报告表与接口 | `cloud/server/app/routers/harden.py` |
| 报告上传 | `apps/cli/src/sync.ts` 的 `uploadHardenReport()` |
| web 页面 | `cloud/web/src/views/AgentsView.vue`（熔断）、`HardenView.vue`（报告） |

## 4. 测试

```bash
pnpm --filter @podsec/cli test -- quarantine-sync harden-upload   # 机器侧三条安全规则
cd cloud/server && uv run pytest tests/test_quarantine.py tests/test_harden.py -q
```
