# ebpf-quic-proxy

基于 **C++17 / standalone asio** 的多协议反向代理：支持经典 **TCP + HTTP/1.1** 与 **UDP + QUIC (HTTP/3)**，两条传输路径共享同一套代理核心（路由 / 后端池 / 编解码抽象）。

> ⚠️ **Phase 2 实验期**。TCP 路径可用；QUIC/HTTP/3 路径已能用真实客户端（curl/ngtcp2）走通端到端（含 interop 修复，见下）。

## 架构：统一单入口 + co-located worker（Model A）

- **1 个 ingress 线程**：承担 TCP `accept` + QUIC demux（共享 UDP socket 收包、按 DCID 查 CID 表投递），与 worker 之间唯一交接点是 `io_context::post`。
- **N 个 worker 线程**：每 worker 是一条 io_context 线程，**同线程** 挂着前端 socket、QUIC server 引擎、relay 业务、私有后端连接池（co-located，请求的生死不跨线程）。
- 连接迁移安全：QUIC 由 CID 标识，不依赖内核 `SO_REUSEPORT` 分片（macOS 不分发；Linux 4 元组分发会在迁移时断裂）。详见 [docs/design-quic-demux.md](docs/design-quic-demux.md)。

```
ingress 线程： TCP accept ──post──▶ worker i（TCP fd）
              UDP demux ──post──▶ worker i（QUIC 包，查 CID 表）
worker i：    前端 socket + QUIC 引擎 + relay + 私有后端池（一条线程）
总线程数 = N + 1
```

## 特性

- **TCP/QUIC 统一工作模型**：`ITransportSession` / `ITransportStream` 屏蔽传输差异，`ICodec` 屏蔽 H1/H3 差异。
- **QUIC 共享 UDP 入口**：`QuicPacketDemux` 用 `lsquic_dcid_from_packet` 解析 DCID 并路由到 worker 的 `QuicServerEngine`；发送走 `ea_packets_out` 同步契约。
- **优雅关闭**：`ReverseProxyServer` 编排 N+1 线程生命周期；`run()` 阻塞并装 SIGINT/SIGTERM。停服时先停止接入（cancel acceptor + demux）——TCP 侧空闲 keep-alive 连接立即 `shutdown_send`（FIN）、在途请求给 `grace` 时间完成后 FIN + drain 到 EOF（`close()` 不触发 RST）；QUIC 侧先发 **GOAWAY**（在途 H3 流继续），grace 后对剩余连接发 **CONNECTION_CLOSE** 再硬停。
- **IPv4/IPv6 双栈**：`dual_stack = true` 时前端 TCP/QUIC 同时监听两个族（后端 TCP 本就双栈、QUIC 上游按解析结果自动选族）。IPv6 不可用 → 响亮警告 + 回退 IPv4-only，绝不静默。
- **基于主机的路由** + **私有后端池**：H1 后端 keep-alive 复用；H3 后端经 QUIC client 引擎多路复用（一条连接 N 请求流）。
- **正向代理**：absolute-form 目标（`GET http://host/path`）直连 URL authority；https 走 `CONNECT` 隧道。
- **字节桥隧道**：CONNECT 与 WebSocket Upgrade（101）切原始字节双向泵，完全绕过 codec。
- **H3 编解码**：头部走 lsquic 原生 QPACK/header-set（ADR-8 路线 B），本体为裸 DATA 字节流。
- **lsquic + BoringSSL** 内嵌 vendored；含一处 HTTP/3 interop 补丁（见下），构建钩子自动维护。

## 目录结构

```
src/
  main.cpp                      入口：加载配置 → ReverseProxyServer.run()（阻塞，信号优雅退出）
  config.{h,cpp}                TOML 配置解析
  transport/
    itransport_session.h        连接抽象
    itransport_stream.h         流抽象（字节流 + header-set 通道）
    tcp_transport.{h,cpp}       TCP + HTTP/1.1 传输
    quic_transport.{h,cpp}      QUIC 引擎（QuicServerEngine / 客户端），lsquic 驱动
    quic_demux.{h,cpp}          QuicPacketDemux：共享 UDP socket + CID 路由（统一单入口）
  proxy/
    reverse_proxy_server.{h,cpp} 整个代理编排类：ingress+worker 线程、run()/start()/wait()/stop()
    proxy_core.{h,cpp}          核心：接收 → 路由 → 转发（TCP/QUIC 同一入口）
    router.{h,cpp}              基于 Host 的路由表
    upstream_pool.{h,cpp}       后端端点池（轮询，lazy 连接，worker 私有）
    relay_session.{h,cpp}       前后端字节/帧中继（含优雅关闭 drain）
  codec/
    icodec.h                    编解码抽象
    h1_codec.{h,cpp}            HTTP/1.1 编解码
    h3_codec.{h,cpp}            HTTP/3（varint / 帧类型 / QPACK 结果解释）
    http_message.{h,cpp}        请求/响应 IR
examples/
  quic_demux_demo.cpp           CID 解复用最小原型（已验证迁移安全）
  lsquic_h3_server_min.cpp      lsquic 握手互操作复现/验证 harness（C++20）
  mini_quic_demo.cpp            零依赖迷你 QUIC 引擎演示（教学用，独立编译）
scripts/
  ensure_lsquic_patch.sh        构建钩子：保持 interop 补丁应用（CMake target: lsquic-patch-guard）
third_party/                    vendored lsquic + BoringSSL（gitignored）
tests/                          单元测试（H1/H3 codec、config，Catch2）
docs/                           架构 / 传输 / 设计决策 / QUIC demux / interop 报告
```

## 构建

依赖链：**Go → BoringSSL → lsquic → 项目**。vendored lsquic 硬绑 BoringSSL，BoringSSL 需要 Go。

```bash
# 1) 构建 BoringSSL（需要 Go）
cmake -S third_party/boringssl -B third_party/boringssl/build -DCMAKE_BUILD_TYPE=Release
cmake --build third_party/boringssl/build -j

# 2) 构建 lsquic（对 BoringSSL）—— 先确保 interop 补丁已应用：
bash scripts/ensure_lsquic_patch.sh    # 自动把 docs/lsquic-4.7.0-http3-interop-a-b.patch 应用到 vendored lsquic
cmake -S third_party/lsquic -B third_party/lsquic/build \
    -DLSQUIC_LIBSSL=BORINGSSL \
    -DBORINGSSL_INCLUDE=$PWD/third_party/boringssl/include \
    -DBORINGSSL_LIB_ssl=$PWD/third_party/boringssl/build/libssl.a \
    -DBORINGSSL_LIB_crypto=$PWD/third_party/boringssl/build/libcrypto.a \
    -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=OFF
cmake --build third_party/lsquic/build -j

# 3) 配置并构建代理（核心 C++17；lsquic_h3_min 示例按 C++20）
cmake -S . -B build
cmake --build build -j

# 4) 运行（默认 config: proxy.toml；QUIC 需 certs/cert.pem + key.pem）
./build/ebpf-quic-proxy proxy.toml
```

> **为什么有 interop 补丁**：vendored lsquic 4.7.0 有两个缺陷导致无法与严格客户端（curl/ngtcp2）握手——无 SNI 时 `CERT_CB_ERROR`，以及 ack-eliciting Initial 未填充到 1200 字节（RFC 9000 §14.1）。两处补丁修复后 `curl -k --http3-only` 在 `localhost`/`127.0.0.1` 均返回 200。调查报告：`docs/lsquic-handshake-bug-report.md`。构建钩子 `lsquic-patch-guard` 会在每次链接 lsquic 的构建前自动重新应用补丁，并在 `liblsquic.a` 由未打补丁源码编出时响亮失败。

## 配置（proxy.toml）

```toml
[listen]
address       = "0.0.0.0"
port          = 8080
num_threads   = 4            # worker 数：1 ingress + N worker
dual_stack    = true         # 前端同时监听 IPv4 + IPv6（见下）
idle_timeout  = 30           # 连接空闲超时（秒）；0 = 关闭
quic_port     = 8443         # QUIC UDP 端口；0 = 关闭 QUIC
quic_cert_file = "certs/cert.pem"
quic_key_file  = "certs/key.pem"

[[backends]]
id = "api"
host = "127.0.0.1"
port = 9001
weight = 1
# protocol = "h1" | "h3"   # 默认 h1；h3 = 经 QUIC/HTTP/3 到达后端

[[routes]]
host = "api.example.com"
backend = "api"

[[routes]]
host = "*"
backend = "api"             # 兜底路由
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen.address` | `0.0.0.0` | TCP 监听地址（ingress accept） |
| `listen.port` | `8080` | TCP/HTTP/1.1 端口 |
| `listen.num_threads` | `1` | **worker 数**：总线程 = `num_threads` + 1（ingress）。每 worker = 一条 io_context 线程，host 前端 + QUIC 引擎 + relay + 私有后端池 |
| `listen.dual_stack` | `false` | 前端同时监听 IPv4 + IPv6：TCP acceptor 绑 `::` + `IPV6_V6ONLY=0`，QUIC demux 多开一个 v6 UDP socket（双 socket，v4 不做 v4-mapped）。IPv6 不可用时**响亮警告并回退 IPv4-only**（不静默）。后端侧 TCP 已双栈（resolver），QUIC 上游按解析结果族自动选 socket |
| `listen.idle_timeout` | `30` | 单连接空闲超时（秒，`0` 关闭）。relay 在最后一次活动后 N 秒无活动即 teardown，释放 session/fd/后端端口；在请求解析/响应/隧道流量等阶段边界重置（滑动窗口，见 ADR-10） |
| `listen.quic_port` | `0` | QUIC UDP 端口（ingress 共享 socket），`0` 关闭 QUIC |
| `listen.quic_cert_file` / `quic_key_file` | `certs/cert.pem` / `key.pem` | QUIC TLS 证书（所有 worker 共享同一只读 ctx） |
| `backends[].id/host/port/weight` | — | 后端端点 |
| `backends[].protocol` | `"h1"` | `"h1"` = TCP/HTTP/1.1，`"h3"` = QUIC/HTTP/3 上游 |
| `routes[].host/backend` | — | 路由规则，`host = "*"` 兜底 |

## 测试

```bash
cmake --build build --target proxy_tests -j
./build/proxy_tests        # 140 assertions / 24 cases
```

## 文档

- [架构](docs/architecture.md) — 组件、分层、数据流
- [传输层深入](docs/transport.md) — UDP/QUIC/lsquic 驱动模型、并发与所有权
- [RelaySession 相位机](docs/relay-session.md) — 核心状态机逐相位详解（含"隐式状态 vs 显式 enum/跳转表"讨论）
- [HTTP/1.1 语义速查](docs/http-primer.md) — 标准知识 ↔ codec 代码行号对照，读 H1Codec 的入口
- [QUIC demux 设计蓝图](docs/design-quic-demux.md) — Model A：统一单入口 + co-located worker、CID 路由、发送契约、优雅关闭
- [单 ingress 收包优化设计](docs/ingress-dispatch.md) — QUIC 入站开销分解（二次拷贝/堆分配/post 唤醒）+ 缓冲池/批量/多线程分发方案
- [设计决策与开放问题](docs/design-decisions.md) — ADR（含 H3 codec 路线 B / lsquic 原生 QPACK）
- [CI 规范](docs/ci.md) — 构建链顺序、验证清单、平台差异、third_party 拉取约束
- [lsquic 握手互操作报告](docs/lsquic-handshake-bug-report.md) — 三个缺陷定位 + 验证修复（upstream issue #680 草稿）
- [QUIC 崩溃排查记录](docs/crash_report.md) — `lsquic_global_init` 缺失导致 SIGABRT 的根因与修复
- [构建细节](docs/build.md)

## 学习参考

[examples/mini_quic_demo.cpp](examples/mini_quic_demo.cpp) 是一个零依赖、单文件的迷你 QUIC 引擎，
接口风格与 lsquic 一致（`packet_in` / `process_conns` / 函数指针回调表 / conn_ctx），
用来直观演示 CID 解复用、wantread 电平信号、on_read 的触发时机、同步发包与 ctx 生命周期：

```bash
clang++ -std=c++20 examples/mini_quic_demo.cpp -o /tmp/mini_quic_demo && /tmp/mini_quic_demo
```

## License

MIT，见 [LICENSE](LICENSE)。
