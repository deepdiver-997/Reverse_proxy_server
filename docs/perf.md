# 性能基准与方法论

优化前必须有可复现的数字。本文记录工具、方法与历次基线；每次性能相关改动后
在"历次基线"表追加一行。

## 工具

- **压测客户端**：vendored lsquic 自带 `http_client`。构建（一次）：
  ```bash
  cmake -S third_party/lsquic -B third_party/lsquic/build -DLSQUIC_BIN=ON
  cmake --build third_party/lsquic/build --target http_client -j8
  ```
- **基准脚本**：`scripts/bench.sh CONNS REQS`（`-R` 自动按 连接数 均摊）。
- **指标端点**：`proxy.toml [listen] stats_port = 9100`（127.0.0.1 only），
  `curl 127.0.0.1:9100` 输出 Prometheus 风格计数：连接数、请求数、响应 ok/err、
  新建后端连接数、后端延迟 sum/count（µs）。
- **后端**：`python3 -m http.server 3000`（单线程，自身是瓶颈之一——仅适合做
  回归基线，不适合测代理极限吞吐）。

## 已知客户端工具坑（重要）

1. `-R` 必须设为约 `reqs/conns`：`http_client` 的第一条连接会一次性吃光
   `-r` 全部请求额度，其余连接永不创建（`http_client_on_new_conn` 里
   `MIN(total, reqs_per_conn)` 的分发逻辑）。`bench.sh` 已自动均摊。
2. **单连接 ~100 条流的额度上限**：lsquic 默认 MAX_STREAMS 初始额度用完后，
   客户端等服务器补充信用的间隙表现为每请求数百毫秒的停顿；额度耗尽后连接
   静默，直到代理 idle_timeout（默认 30s）将其关闭。表现为"每连接恰 100 条
   响应、耗时恰好 ~36.5s"。**这是 lsquic 客户端行为，不是代理 bug**；解决：
   多连接分摊（bench.sh 已做）或 `-w N` 流水线并发。
3. `http_client` 每连接默认串行（`-w 1`）：测出的 rps 由客户端节奏主导，
   **不代表代理吞吐上限**。基线数字仅用于回归对照。

## 基线环境

macOS arm64（darwin 24.6），环回 UDP/TCP，`num_threads = 1`，
后端 `python3 -m http.server 3000`，lsquic f906160（含 PR #690）。

## 历次基线

| 日期 | 配置 | 结果 | 备注 |
|---|---|---|---|
| 2026-09-11 | 1 conn / 500 req 串行 | 客户端在 100 req 处因流额度停顿，2.7 rps | 客户端节奏主导 |
| 2026-09-11 | 10 conn / 1000 req | ~14 rps，后端延迟均值 ~626 µs | 同上；代理侧 TTFB 均值 ~12 ms |

## 解读

- 代理侧每请求开销很小（后端延迟实测 ~0.6 ms，客户端 TTFB 均值 ~12 ms）；
  当前数字被**客户端串行节奏 + MAX_STREAMS 额度**支配，不能反映代理容量。
- 下一步（路线图 Phase 2/3，见 README / 本目录）：多核 ingress
  （SO_REUSEPORT + BPF DCID steering）、egress 批量 + 缓冲池。做之前先换一个
  更强的压测源（h2load h3 版或自写 h3 loadgen），并把后端换成非阻塞 echo。

## 重大发现：H3 keep-alive 在默认配置下每连接 ~100 请求即饿死（2026-09-11）

现象：每连接恰好 100 条响应后 stall，30s idle 后被代理回收（曾误判为噪声/环境问题）。
两层原因：

1. **lsquic 传输参数只授初始信用**：TP 里广播的 `init_max_streams_bidi` 来自
   `es_init_max_streams_bidi`（默认 100），与 `es_max_streams_in` 是两个独立设置。
   只调 `es_max_streams_in` 不改变初始信用。
2. **relay 对 H3 流不关闭**：`after_client_response()` 对 h3 也走 H1 的
   keep-alive 逻辑（在已 FIN 的流上等下一个请求），流对象挂到 30s idle 超时，
   服务器侧流槽位被占满后 lsquic 丢弃新流帧。

修复：a) `after_client_response` 对 h3 改为 drain-to-EOF + teardown（每流一发即关）；
b) 新增 `proxy.toml max_streams_in`（同时设 `es_init_max_streams_bidi` 与
`es_max_streams_in`，默认 0 = lsquic 原值 100；基准/生产建议 1000+）。

效果（10 conn × -w 4，asyncio 后端）：修复前 100 req/36.6s（2.7 rps）→
修复后 **5000 req/2.29s（≈2185 rps）**。

注意：debug 级 lsquic 日志本身会让吞吐降 ~3.7 倍（8.5s vs 2.3s）——压测时必须
关闭（`enable-lsquic-info-log.patch` 仅用于诊断）。

## 历次基线（修订）

| 日期 | 配置 | 结果 | 备注 |
|---|---|---|---|
| 2026-09-11 修复前 | 10 conn / w4 / 5000 req | 100 req 后 stall（2.7 rps） | MAX_STREAMS 初始信用 + h3 流不关闭 |
| 2026-09-11 修复后 | 10 conn / w4 / 5000 req | **2185 rps**，全部 200 | asyncio 后端 |
| 2026-09-11 修复后 | 50 conn / w8 / 20000 req | ~86 rps | 多连接反而劣化——待查（ingress 单线程 / 客户端 50 连接事件循环），Phase 2 入口 |


## 50 连接劣化归因（2026-09-11）

50 conn × w8 时吞吐降至 ~86 rps。归因实验：

- 压测期间采样 CPU：**代理进程 100%（单核饱和）**，客户端 1%，后端 0.1%
  → 不是客户端问题，无需改客户端。
- `sample` 热点栈：worker 线程 `lsquic_engine_process_conns` +
  `lsquic_stream_dispatch_read_events`（relay/H3 处理本身）；ingress demux
  占比很小。
- 结论：**单 worker 打满**。num_threads>1 在当前 src-IP 哈希下对环回无效
  （同 IP 全落 worker 0）——这正是 Phase 2 要解决的，见
  docs/design-multi-ingress.md（路由字节 CID 方案）。
## Phase 2a 验收（路由字节 CID，2026-09-11）

| num_threads | 50 conn × w8 / 20000 req | 吞吐 |
|---|---|---|
| 1 | 86.2s | ~231 rps（单 worker 饱和，400 并发流下非线性劣化） |
| 2 | 10.1s | ~1980 rps |
| 4 | 5.7s | ~3490 rps |

实施：`ea_generate_scid` 产出 SCID[0]=worker idx；demux 未知 CID 先查路由字节、
否则按 DCID 字节哈希（替换原 src-IP 哈希，解除环回/同 NAT 倾斜）。零错误。
NT=1 的非线性劣化与 50 连接下的客户端行为待深入；NT≥2 后悬崖消失。
