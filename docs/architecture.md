# 系统架构

反向代理核心把「传输」与「协议」解耦为两层抽象，使 TCP/HTTP/1.1 与 QUIC/HTTP/3 共用同一套路由/转发逻辑；HTTP/3 既可作为**客户端**接入，也可作为**上游**（QUIC client 引擎）被代理。

## 分层总览

```
                        ┌──────────────────────────────────────────┐
                        │                ProxyCore                 │
                        │   on_session / on_stream（组装 + 注入）    │
                        └───────┬──────────────────────┬───────────┘
                                │                      │
                 ITransportSession / ITransportStream  │   ICodec（四方）
                 ┌─────────────────────────────┐       │   ┌────────────────────┐
                 │ TCP 传输（H1 客户端/上游）    │       │   │ H1Codec            │
                 │ QUIC server 引擎（H3 客户端）│       │   │ H3Codec            │
                 │ QUIC client 引擎（H3 上游）  │       │   │ (wire <-> IR 双向)  │
                 └─────────────┬───────────────┘       │   └────────────────────┘
                               │                       │
                    Router（基于 Host 的路由表）
                    UpstreamPool（协议感知连接池）
                    RelaySession（相位机：请求 → 选后端 → 响应 → 回环/字节桥）
```

- **传输层**：`ITransportStream` 是一条有序可靠字节流（TCP 连接或 QUIC 流），协议无关——字节桥因此可以完全绕过 codec。
- **编解码层**：`ICodec` 做 wire ↔ IR 双向转换；HTTP 语义（路由/keep-alive/改写）都在 IR 层，不感知传输。
- **核心层**：`RelaySession` 把「客户端流」和「后端流」泵起来；协议差异只在「选哪个 codec / 哪个池」时体现。

## 传输层（transport/）

| 抽象 | 语义 | TCP | QUIC server（H3 客户端） | QUIC client（H3 上游） |
|---|---|---|---|---|
| 引擎/监听 | 接受/发起连接 | `TcpTransportListener`（acceptor） | `QuicTransportListener`（UDP + lsquic server 引擎） | `QuicClientEngine`（UDP + lsquic client 引擎） |
| Session | 一条「连接」 | `TcpTransportSession`（1 session = 1 连接 = 1 stream） | `QuicTransportSession`（1 连接 = N 流） | 复用 `QuicTransportSession` |
| Stream | 有序可靠字节流 | `TcpTransportStream`（asio socket） | `QuicTransportStream`（lsquic stream） | 复用 `QuicTransportStream` |

关键差异：
- **TCP 里 session 与 stream 1:1 一起出生；QUIC 里 1 个连接上可动态开多条流**（请求多路复用）。因此 `ITransportSession::set_new_stream_cb` 在 TCP 下同步触发一次、QUIC 下异步触发 N 次。
- **lsquic 强制一引擎一角色**（源码断言，无 server|client 合并）：H3 客户端由 `QuicTransportListener` 的 server 引擎服务；H3 上游由 `QuicClientEngine`（`LSENG_HTTP`）主动发起出站连接。两个引擎各有独立 UDP socket + 驱动循环，但**共享流/会话类与 HTTP/3 头集接口（HSI）**——流的读写、QPACK 解码、`get_hset`/`send_headers` 全部角色无关。

H3 上游连接复用的驱动模型：`QuicClientEngine::connect(endpoint)` → `lsquic_engine_connect`（同步触发 `on_new_conn`，把 endpoint 挂到 session）→ 握手期间调用 `lsquic_conn_make_stream`，流在握手完成后由 `on_new_stream` 送达（无需显式等 `on_conn_established`，4.7 只有可选的 `on_hsk_done`）。详见 [transport.md](transport.md) 与 [ADR-9](design-decisions.md#adr-9quic-客户端引擎h3-上游)。

## 编解码层（codec/）

`ICodec` 提供四方接口：`async_parse_request` / `async_write_request` / `async_parse_response` / `async_write_response`。

- `H1Codec`：HTTP/1.1 解析/序列化（请求行/状态行、chunked、keep_alive 计算、absolute-form 归一化）。
- `H3Codec`：HTTP/3。头部走 **lsquic 原生 QPACK**（ADR-8 路线 B）：transport 把解码出的**原始头列表**（含 pseudo-header）交给 codec，codec 解释成请求或响应 IR（`request_head_from_headers` / `response_head_from_headers`）。body 是 DATA 帧 = 流的 FIN 定界字节。写请求/响应时剥 hop-by-hop 头（RFC 9113 §8.1.2.2）并 **FIN 流**（HTTP/3 消息以 FIN 结束，见 ADR-9 的坑 2）。

**客户端侧 codec 按 transport 选**：`ProxyCore::on_session` 按 `session->protocol()` 选 H1 或 H3。
**后端侧 codec 按 endpoint 协议选**：`RelaySession::use_backend` 按 `BackendEndpoint.protocol`（TCP→H1，QUIC→H3）决定，因此一条中继可以「H3 客户端 → H1 后端」或「H3 客户端 → H3 上游」。

## 代理核心（proxy/）

- `Router`：`host_match → backend_id` 静态路由表，`*` 兜底。
- `UpstreamPool`：协议感知后端连接池。
  - **TCP 后端**（H1）：keep-alive 池——`release()` 归还空闲连接、`async_connect` 优先复用；陈旧连接写入失败时重试一次新鲜连接（仅无请求体时）。
  - **QUIC 后端**（`protocol="h3"`）：经 `QuicClientEngine` 复用已建立连接——每请求开一条新流（多路复用，一条连接 N 请求流）。连接关闭时从复用表自清理。
- `RelaySession`：每个客户端流一个 session，**相位机**（ADR-7）：
  1. **Request**：解析客户端请求 → 特殊分支（CONNECT → 字节桥；absolute-form → 正向代理直连）→ 否则路由
  2. 连接后端（TCP 池 / QUIC 复用）→ 写请求
  3. **Response**：解析后端响应 → 写回客户端 → 按 codec 的 `keep_alive` 决定回环（H1 客户端保活）或 teardown
  4. **字节桥模式**：CONNECT 隧道 / WebSocket 101 后，两个独立事件驱动字节泵（client ⇄ target）直到任一端关闭，完全绕过 codec

## 数据流

### H1 反代（TCP 客户端 → H1 后端）

```
client ─▶ TcpTransportListener.async_accept ─▶ TcpTransportSession
      ─▶ on_stream：选 H1Codec ─▶ RelaySession.request_phase
      ─▶ H1Codec.async_parse_request ─▶ Router.route(head)
      ─▶ UpstreamPool.async_connect（TCP keep-alive 池复用）
      ─▶ H1Codec.async_write_request（写请求行 + 头 + body）
      ─▶ H1Codec.async_parse_response（CL / chunked / close 定界）
      ─▶ H1Codec.async_write_response ─▶ 按 keep_alive 回环或 teardown
```

### H3 客户端 → H1 后端

```
client ─▶ QuicTransportListener（一个 UDP socket 收所有人，按 CID 解复用）
      ─▶ lsquic_engine_packet_in ─▶ on_new_stream ─▶ ProxyCore.on_stream（H3Codec）
      ─▶ RelaySession：H3Codec.async_parse_request（QPACK 解码头 → IR，body 为 DATA 读到 FIN）
      ─▶ 路由 ─▶ TCP 后端池 ─▶ H1Codec.async_write_request
      ─▶ H1 响应解析 ─▶ H3Codec.async_write_response（send_headers + DATA + FIN）
```

### H3 客户端 → H3 上游（全 QUIC 链路，proxy→proxy）

```
quic-go ─▶ proxy B: H3 server 引擎 ─▶ RelaySession（H3 client codec）
        ─▶ 路由到 protocol="h3" 后端 ─▶ UpstreamPool: QuicClientEngine 复用连接
        ─▶ 新流 ─▶ H3Codec.async_write_request（pseudo-headers + FIN）
        ─▶ proxy A: H3 server 引擎 ─▶ RelaySession ─▶ H1 后端
        ─▶ 响应沿原路返回（proxy A H3 响应 + FIN → proxy B H3 上游解析 → 客户端）
```

### 字节桥（CONNECT / WebSocket）

```
client ─▶ RelaySession 识别 CONNECT host:port 或 Upgrade 请求
      ─▶ 直连目标 / 转发 Upgrade ─▶ 200 / 101
      ─▶ bridge_mode()：pump_bytes(client→backend) + pump_bytes(backend→client)
      ─▶ 任一端 EOF/错误 ─▶ teardown（字节原样双向，不经 codec）
```

### 正向代理 absolute-form

```
client 发 GET http://host/path（absolute-form）─▶ H1Codec 归一化为 origin-form
      ─▶ head.absolute_target ─▶ RelaySession 直连 URL 的 authority（跳过路由表）
      ─▶ Host 头强制 = authority ─▶ 转发 origin-form 请求
      （https absolute-form 拒绝，提示走 CONNECT）
```

## 线程模型

- 默认 `num_threads = 1`：整个 io_context 单线程驱动，**没有并发问题**。
- 现在有**两个 lsquic 引擎**（server + client），都**非线程安全**，只允许被同一线程驱动。两者各有自己的 UDP socket + asio 定时器，在同一 io_context 上交错运行，互不并发。
- 要扩展多核，正确做法是**按连接（CID）分片到多对引擎**，每引擎绑一个线程（见设计决策），而不是给单引擎加锁。

## 生命周期

- `QuicTransportSession` / `QuicTransportStream` **自持**一份 `shared_ptr`（`adopt_self()`）——刻意可破的循环，保证对象活到连接/流结束，无需注册表。
- 连接关闭：`on_conn_closed`（lsquic 对该连接的最后一次回调）先取保活拷贝、再 `on_closed()`、最后 `release_self()`。**`on_closed()` 里必须 `lsquic_conn_set_ctx(conn, NULL)`** 清掉 conn_ctx，否则 lsquic 销毁连接时 `assert(cn_conn_ctx == NULL)` abort（ADR-9 坑 1）。析构发生在最后一次回调返回之后，避免在成员函数内销毁 `this`。
- 流关闭：`on_close` 置 `stream_=nullptr`、发 EOF 回调、`release_self()`；`on_close_cb` 先取保活拷贝。
