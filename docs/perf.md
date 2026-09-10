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
