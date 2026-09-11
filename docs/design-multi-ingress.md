# 设计：多核 ingress 与 DCID 亲和路由（Phase 2）

状态：设计稿 v1（2026-09-11）。前置数据：docs/perf.md 归因一节。

## 1. 瓶颈证据（50 conn × w8，环回）

- 代理进程 100% CPU，客户端 1%，后端 0.1% —— 服务端单核饱和。
- `sample` 热点：worker 线程 `lsquic_engine_process_conns` +
  `lsquic_stream_dispatch_read_events` 占满；ingress demux 采样占比很小。
- 结论：**单 worker 的 QUIC/H3/relay 处理是瓶颈**，多 worker 是正确方向；
  ingress 批量化（Phase 3）在多 worker 之后才有意义。

## 2. 为什么现在不能开多 worker

`QuicPacketDemux::route()` 对未知 CID（新连接首包）按**源 IP** 哈希选 worker：

- 环回压测下所有连接同 IP → 全部落到 worker 0，多 worker 无效；
- 真实部署同 NAT 多客户端也会倾斜；
- 改成"未知 CID 按 DCID 字节哈希"会重演 Retry 亲和问题：post-Retry Initial 的
  DCID 是引擎新生成的 Retry SCID，哈希值随机 → 可能落到不持有连接的 worker
  （见 docs/local/lsquic-retry-scid-demux-routing-bug.md）。

## 3. 方案：路由字节 CID（routing-byte CID）

核心想法（QUIC-LB 同款）：**服务器生成的每个 CID，首字节编码归属 worker**。

```
SCID = [worker_idx (1B)] [random (len-1 B)]
```

- `QuicServerEngine` 通过 lsquic 的 `ea_generate_scid` 回调产出带路由字节的 CID
  （harness 时代已验证过该回调可用）。
- demux 对未知 CID：首字节 < num_workers → 视为 worker 提示直接路由；
  否则回退现有 IP 哈希（首个 Initial 的 DCID 是客户端随机 ODCID，落哪个 worker
  哪个 worker 成为归属——一致性自洽）。
- **Retry 亲和**：Retry SCID 也由归属 worker 的引擎生成（路由字节正确）→
  post-Retry 包正确回到归属 worker，无需登记表。
- **迁移/NAT 重绑定**：DCID 不变 → 路由字节不变 → 亲和保持（优于 IP 哈希）。
- 真实多客户端 IP 分布 + 路由字节双保险，worker 间负载均衡由新连接的首包哈希
  （或重试后的 SCID 路由字节）决定。

## 4. 实施阶段

### Phase 2a（纯用户态，macOS/Linux 通用，先做）
1. `ea_generate_scid`：首字节 = worker idx。
2. demux `route()`：未知 CID 首字节命中 worker 范围 → 直投；否则回退 IP 哈希。
3. 代理.toml 暴露 `num_threads` 已有；回归基准：num_threads = 1/2/4，环回
   期望近线性（单 worker 饱和 ~2185 rps → 4 worker 目标 >6000 rps）。

### Phase 2b（Linux only）
1. 每 worker 独立 UDP socket（SO_REUSEPORT）替代共享 demux socket；
2. `SK_REUSEPORT` BPF：解析 UDP payload → 长头取 SCID / 短头取 DCID 的首字节
   选 socket；ODCID（非路由字节开头）用 DCID 哈希；
3. 收包零拷贝直入 worker，消除 ingress 线程与跨线程 post；
4. macOS 保持 Phase 2a 用户态 demux（eBPF 不可用），行为一致。

### Phase 2c（可选）
- 上游建议：lsquic 原生支持"CID 前缀路由"配置化（类似 QUIC-LB 的
  routing bits 规范），减少对 ea_generate_scid 的依赖。

## 5. 风险与权衡

- 路由字节消耗 1 字节 CID 熵（es_scid_len=8，可接受；不得低于 4B 随机）。
- BPF 程序解析 QUIC 头需处理变长 DCID 与版本分支，Phase 2b 用尾调用拆分。
- worker 数 > 256 才会溢出路由字节，短期内不是问题。
- 卸载路径：worker 下线时其 CID 前缀的连接需要排水（现有 graceful 机制 + 老
  CID 自然过期）。

## 6. 验收标准

- 环回 num_threads=1/2/4 吞吐近线性（±20%）；
- 迁移模拟（换源端口）不断流；
- Retry 开启时 post-Retry 包 100% 到达归属 worker（demux 日志计数）；
- 现有 proxy_tests + run_matrix 回归全绿。
