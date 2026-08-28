# ebpf-quic-proxy

基于 **C++20 / Boost.Asio** 的多协议反向代理：支持经典 **TCP + HTTP/1.1** 与实验性的 **UDP + QUIC (HTTP/3)**，两条传输路径共享同一套代理核心（路由 / 后端池 / 编解码抽象）。

> ⚠️ 项目处于 **Phase 2 实验期**。TCP/HTTP/1.1 路径可用；QUIC 传输层已接入 lsquic，但 HTTP/3 头部处理方式（手写帧解析 vs lsquic 原生 H3）仍是一个未决设计，见 [docs/design-decisions.md](docs/design-decisions.md)。

## 特性

- **双协议监听**：同一个 `ProxyCore` 同时挂 TCP 与 QUIC 两个监听器，按传输协议自动选择编解码器。
- **传输抽象**：`ITransportSession` / `ITransportStream` 屏蔽 TCP/QUIC 差异，`ICodec` 屏蔽 H1/H3 差异。
- **基于主机的路由** + **后端轮询**（upstream pool）。
- **lsquic + BoringSSL**：内嵌 vendored 依赖，无需系统级 QUIC 栈。
- 请求/响应转发逻辑与传输解耦，便于后续扩展 WebSocket、gRPC 等。

## 目录结构

```
src/
  main.cpp                    入口：加载配置、起事件循环
  config.{h,cpp}              TOML 配置解析
  transport/
    itransport_session.h      session 抽象（连接）
    itransport_stream.h       stream 抽象（字节流）
    tcp_transport.{h,cpp}     TCP + HTTP/1.1 传输
    quic_transport.{h,cpp}    QUIC + lsquic 传输（UDP 驱动）
  proxy/
    proxy_core.{h,cpp}        核心：接受连接 → 路由 → 转发
    router.{h,cpp}            基于 Host 的路由表
    upstream_pool.{h,cpp}     后端端点池（轮询，lazy 连接）
  codec/
    icodec.h                  编解码抽象
    h1_codec.{h,cpp}          HTTP/1.1 编解码
    h3_codec.{h,cpp}          HTTP/3 帧编解码（手写，无 QPACK）
    http_message.{h,cpp}      请求/响应 IR
third_party/                  vendored lsquic + BoringSSL
tests/                        单元测试（H1/H3 codec）
docs/                         架构、传输层、设计决策文档
```

## 构建

依赖：CMake ≥ 3.16，Clang，Boost.Asio（头文件，`/opt/homebrew/include`），spdlog，toml11。

```bash
# 1) 预构建 lsquic + BoringSSL（第三方目录内，参照其自身构建脚本）
#    产物需出现在 third_party/lsquic/build/src/liblsquic/liblsquic.a

# 2) 配置并构建代理
cmake -S . -B build
cmake --build build -j

# 3) 运行
./build/ebpf-quic-proxy proxy.toml
```

## 配置（proxy.toml）

```toml
[listen]
address    = "0.0.0.0"
port       = 8080
num_threads = 1          # ⚠️ QUIC 引擎非线程安全：保持 1 或按连接分片多引擎

# QUIC (HTTP/3)：quic_port = 0 表示关闭
quic_port       = 443
quic_cert_file  = "certs/cert.pem"
quic_key_file   = "certs/key.pem"

[[backends]]
id   = "api"
host = "127.0.0.1"
port = 9001
weight = 1

[[routes]]
host = "api.example.com"
backend = "api"
```

字段说明：

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen.address` | `0.0.0.0` | 监听地址 |
| `listen.port` | `8080` | TCP/HTTP/1.1 端口 |
| `listen.num_threads` | `1` | io_context 工作线程数。**QUIC 引擎不允许并发驱动**，>1 时需先按连接分片到多个引擎（见 transport 文档） |
| `listen.quic_port` | `0` | QUIC UDP 端口，`0` 关闭 QUIC |
| `backends[].id/host/port/weight` | — | 后端端点 |
| `routes[].host/backend` | — | 路由规则，`host = "*"` 兜底 |

## 测试

单元测试（codec 层）随构建产出 `proxy_tests` 目标，使用 Catch2：

```bash
cmake --build build --target proxy_tests -j
./build/proxy_tests
```

## 文档

- [架构](docs/architecture.md) — 组件、分层、数据流
- [传输层深入](docs/transport.md) — UDP/QUIC/lsquic 驱动模型、并发与所有权
- [设计决策与开放问题](docs/design-decisions.md) — ADR + 待决事项
- [QUIC 崩溃排查记录](docs/crash_report.md) — `lsquic_global_init` 缺失导致 SIGABRT 的根因与修复

## 学习参考

[examples/mini_quic_demo.cpp](examples/mini_quic_demo.cpp) 是一个零依赖、单文件的迷你 QUIC 引擎，
接口风格与 lsquic 一致（`packet_in` / `process_conns` / 函数指针回调表 / conn_ctx），
用来直观演示 CID 解复用、wantread 电平信号、on_read 的触发时机、同步发包与 ctx 生命周期：

```bash
clang++ -std=c++20 examples/mini_quic_demo.cpp -o /tmp/mini_quic_demo && /tmp/mini_quic_demo
```

## License

MIT，见 [LICENSE](LICENSE)。
