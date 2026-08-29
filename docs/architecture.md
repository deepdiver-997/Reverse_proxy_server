# 系统架构

反向代理核心把「传输」与「协议」解耦为两层抽象，使得 TCP/HTTP/1.1 与 QUIC/HTTP/3 可以跑在同一套路由/转发逻辑上。

## 分层总览

```
                       ┌────────────────────────────────────────┐
                       │                ProxyCore               │
                       │   on_session / on_stream / forward_*   │
                       └───────┬──────────────────┬─────────────┘
                               │                  │
                  ITransportSession         ICodec (H1Codec / H3Codec)
                  ITransportStream            (协议 <-> IR)
                  ┌─────────────────┐         ┌──────────────┐
                  │ TCP 传输         │         │              │
                  │ QUIC 传输        │         └──────────────┘
                  └────────┬────────┘
                           │  Router（基于 Host） / UpstreamPool（轮询后端）
```

### 传输层（transport/）

| 抽象 | 语义 | TCP 实现 | QUIC 实现 |
|---|---|---|---|
| `ITransportListener` | 接受新连接 | `TcpTransportListener`（acceptor） | `QuicTransportListener`（UDP socket + lsquic 引擎） |
| `ITransportSession` | 一条「连接」 | `TcpTransportSession`（1 session = 1 连接 = 1 stream） | `QuicTransportSession`（1 session = 1 连接 = N streams） |
| `ITransportStream` | 一条有序可靠字节流 | `TcpTransportStream`（asio socket 封装） | `QuicTransportStream`（lsquic stream 封装） |

关键差异：**TCP 里 session 与 stream 是 1:1 且一起出生；QUIC 里 1 个 session 上可以动态开任意多条 stream**（请求多路复用）。因此 `ITransportSession::set_new_stream_cb` 在 TCP 下同步触发一次，在 QUIC 下异步触发 N 次。

### 编解码层（codec/）

`ICodec` 把字节流 ↔ 协议无关的 `HttpRequestHead`/`HttpResponseHead`。`ProxyCore::on_session` 按 `session->protocol()` 选 H1 或 H3 codec。

- `H1Codec`：解析/序列化 HTTP/1.1。
- `H3Codec`：手写 HTTP/3 帧解析（HEADERS/DATA varint 帧头），**无 QPACK**，响应用字面量头。

> ⚠️ 响应方向目前**没有**走 codec：`ProxyCore::forward_request` 把上游返回的 HTTP/1.1 字节直接写回客户端流。对 TCP 客户端成立；对 QUIC/HTTP/3 客户端，响应缺 HEADERS 帧封装，是错误的。见设计决策中的开放问题。

### 代理核心（proxy/）

- `Router`：`host_match → backend_id` 静态路由表，`*` 兜底。
- `UpstreamPool`：后端端点表 + 轮询计数；`async_connect` 每次请求**新开一条 TCP 连接**到后端（lazy，无连接池）。
- `ProxyCore`：组装以上各部分，驱动两条协议路径。

## 数据流

### TCP / HTTP/1.1（Phase 1，可用）

```
client ──▶ TcpTransportListener.async_accept ──▶ TcpTransportSession
        ──▶ on_session：选 H1Codec
        ──▶ set_new_stream_cb 同步触发 ──▶ H1Codec.async_parse_request
        ──▶ Router.route(head) ──▶ UpstreamPool.async_connect(backend)
        ──▶ 上游：写 H1 请求行 + 头 + body
        ──▶ 上游响应：读 8KB → 直接写回 client stream
        ──▶ client_stream.async_shutdown（发 FIN 表示响应结束）
```

### QUIC / HTTP/3（Phase 2，传输层可用）

```
client ──▶ QuicTransportListener（一个 UDP socket 收所有人的包）
        ──▶ lsquic_engine_packet_in：按 Connection ID 解复用
        ──▶ on_new_conn ──▶ QuicTransportSession（adopt_self() 自持所有权）
        ──▶ on_new_stream ──▶ ProxyCore.on_stream（H3Codec）
        ──▶ 路由 / 转发逻辑与 TCP 相同
```

QUIC 侧每一层的事件都由 lsquic 回调驱动，全程同步发生在**同一线程**上。驱动模型详见 [transport.md](transport.md)。

## 线程模型

- 默认 `num_threads = 1`：整个 io_context 单线程，**没有并发问题**。
- **lsquic 引擎非线程安全**，只允许被一个线程驱动。若 `num_threads > 1`，UDP 收包回调（`on_packet`）与定时器回调（`on_tick`）可能被派到不同线程同时摸引擎 → 数据竞争。
- 要扩展多核，正确做法是**按连接（CID）分片到多个引擎**，每个引擎绑一个线程（见设计决策）。

## 生命周期

- `QuicTransportSession` **自持**一份 `shared_ptr`（`self_`，`on_new_conn` 里 `adopt_self()`）——刻意可破的循环，保证对象活到连接结束，无需 listener 维护注册表。
- 连接关闭时 `on_conn_closed_cb`（lsquic 对该连接的最后一次回调）先 `shared_from_this()` 取保活拷贝、再 `on_closed()`、最后 `release_self()` 释放自持；析构发生在该回调返回之后（避免在成员函数内销毁 `this`，且此时 lsquic 已不再引用 conn）。
- `QuicTransportStream` 的 ctx（`lsquic_stream_ctx_t*`）即 stream 对象自身，在构造时 `lsquic_stream_set_ctx` 设置；`on_close` 置 `stream_=nullptr`，析构时据此跳过对已释放 lsquic stream 的访问。
