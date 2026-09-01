# HTTP/1.1 语义速查（映射到本项目代码）

> 目的：把 HTTP 协议的"标准知识"和本项目的具体实现一一对上，让你能读自己的 codec，
> 也能在面试时讲出"我的代码在哪一行做了哪件协议上的事"。
> 配合 `src/codec/h1_codec.cpp`、`src/codec/http_message.{h,cpp}`、`src/proxy/relay_session.cpp` 一起读。

## 0. 一句话模型

HTTP 是**请求/响应**消息协议。一条消息 = 起始行 + 头部 + 空行 + 可选 body：

- 请求：`METHOD SP 目标 SP HTTP版本 CRLF`，然后头部，然后 `\r\n`，然后 body
- 响应：`HTTP版本 SP 状态码 SP 原因短语 CRLF`，然后头部，然后 `\r\n`，然后 body

你的项目把这条线拆成 **IR + 四方 codec**（ADR-6）：
转发逻辑（RelaySession）只碰 IR（`HttpRequestHead`/`HttpResponseHead`），完全不认识线上格式；
`H1Codec`/`H3Codec` 负责 `wire ↔ IR` 双向转换。所以**你只要看懂 IR 和 H1Codec 就掌握了这个代理的 HTTP 语义**。

## 1. 起始行（请求行 / 状态行）

| 概念 | 标准 | 你的代码 |
|---|---|---|
| 请求行 = `METHOD SP target SP version` | RFC 9112 §3 | [h1_codec.cpp:313-327](src/codec/h1_codec.cpp#L313-L327) `parse_header_block` |
| 状态行 = `version SP code SP reason` | RFC 9112 §4 | [h1_codec.cpp:484-502](src/codec/h1_codec.cpp#L484-L502) `parse_response_block` |
| IR 字段 | — | [http_message.h:62-94](src/codec/http_message.h#L62-L94) |

关键点：`version` 是**从线上拿来的原样字符串**（`HTTP/1.1`、`HTTP/1.0`…），write 时再决定怎么写。
[wire_h1_version](src/codec/h1_codec.cpp#L208-L212)：`HTTP/1.x` 保留，其他归一化为 `HTTP/1.1`。
所以 relay 可以安全地"用客户端的版本去跟后端说话"（[relay_session.cpp:326-331](src/proxy/relay_session.cpp#L326-L331)）。

## 2. body 定界 —— HTTP 最容易错的地方，也是你 codec 最核心的活

一个 body 何时结束，有且只有这几种判法，parser 必须严格按优先级：

1. **Content-Length**：固定 N 字节。
2. **Transfer-Encoding: chunked**：每块 = 16 进制长度行 + 数据 + CRLF；最后 `0` 块 + trailer 区。
3. **都没有** → body 以**连接关闭（EOF）**为界（close-delimited）。
4. **某些消息天生无 body**：响应里 1xx、204、304；以及 HEAD 请求的响应（CL 只是"假想长度"）。

你的实现正好逐条对应：

- 请求侧判定：[h1_codec.cpp:272-300](src/codec/h1_codec.cpp#L272-L300) — 有 `content_length` → `StreamBodySource`；没有 → 无 body
- 响应侧判定：[h1_codec.cpp:435-469](src/codec/h1_codec.cpp#L435-L469) — 先判 1xx/204/304 **无 body**；再判 chunked → `ChunkedBodySource`；再判 CL → `StreamBodySource`；都没有 → `StreamEofBodySource` + `close_delimited=true`
- chunked 完整实现：[h1_codec.cpp:15-174](src/codec/h1_codec.cpp#L15-L174) — 长度行（`;` 后的分块扩展丢弃）→ 读载荷 → 跳过 CRLF → `0` 块后消费 trailer
- 三种 BodySource：[http_message.h:118-163](src/codec/http_message.h#L118-L163)

**为什么"无 body 的判定必须先于 CL"**：204/304 即使带了 `Content-Length` 也没有 body，
`StreamBodySource` 会等够 N 字节——**永远等不到 → 挂死**。这也是 HEAD 响应要在 relay 层手动把 body 置空的原因：[relay_session.cpp:321-322](src/proxy/relay_session.cpp#L321-L322)。

**chunked 响应后连接能不能复用**：能，前提是 decoder 把 trailer 也消费掉、停在干净边界。
你的 `ChunkedBodySource` 在 `0` 块后读了 trailer 段：[h1_codec.cpp:58-68](src/codec/h1_codec.cpp#L58-L68)。
（注释里写着"归还连接池前必须消费 trailer"——这正是原因。）

**close-delimited 响应必然不能 keep-alive**：[h1_codec.cpp:471-473](src/codec/h1_codec.cpp#L471-L473) —
body 靠关闭连接定界，这条连接不可能再服务下一个请求。

## 3. keep-alive 语义

- HTTP/1.1 **默认长连接**；HTTP/1.0 **默认短连接**，除非显式 `Connection: keep-alive`。
- 判定优先级：版本默认值 → `Connection: close` 关闭 → `Connection: keep-alive` 打开。

你的实现：[compute_keep_alive](src/codec/h1_codec.cpp#L196-L203)，
版本判断 [version_keeps_alive](src/codec/h1_codec.cpp#L180-L182)。

**这个 flag 是整个相位机回环的依据**：codec 通过回调第 4 个参数传出（[icodec.h:16-24](src/codec/icodec.h#L16-L24)），
RelaySession 据此决定响应写完是**回 request_phase 等下一个请求**还是 teardown（[relay_session.cpp:396-399](src/proxy/relay_session.cpp#L396-L399)）。

注意 H3 的差异：**流恒 keep_alive=false**（HTTP/3 流是一次性的，一条流 = 一个请求/响应；
连接本身在 session 层持续，不靠"流的 keep-alive"）——[h3_codec.cpp:232-233](src/codec/h3_codec.cpp#L232-L233)。

## 4. hop-by-hop 头（代理必须剥掉的头）

- **概念**：某些头只描述"这条连接本身"（framing / 升级 / 代理用），**不能跨连接转发**。
- 标准列表：`Connection`、`Keep-Alive`、`Proxy-Connection`、`Transfer-Encoding`、`Upgrade`（RFC 9113 §8.1.2.2）。
- 深坑：`Connection` 头里列出的每个 token 对应的头，也全是 hop-by-hop（如 `Connection: upgrade`）。

你的实现：[is_hop_by_hop](src/codec/h3_codec.cpp#L201-L209)，写请求/响应时剥离：
[h3_codec.cpp:285-286](src/codec/h3_codec.cpp#L285-L286)、[h3_codec.cpp:323-329](src/codec/h3_codec.cpp#L323-L329)。

**为什么 H1→H3 尤其致命**：H1 上游的 `transfer-encoding: chunked` 描述的是"那条 H1 连接"，H3 的 body
是 DATA 帧 + FIN，天然流式，绝不能把 chunked 带到 H3 响应里。

**H1→H1 转发为什么没显式剥**：同域转发时这些头"语义仍在"（都在 H1 连接上），原样透传大体可用。
但如果后端是 H3 上游，就非剥不可——这正是 codec 按"写路径"做剥离的原因。

## 5. Host / authority、origin-form vs absolute-form

- **反向代理**：客户端给 origin-form（`GET /path`），代理靠 **Host 头**路由到虚拟主机。
- **正向代理**：客户端给 absolute-form（`GET http://host/path`），目标写在请求行里。

你的归一化：[h1_codec.cpp:329-350](src/codec/h1_codec.cpp#L329-L350) — 发现 `://` 就认定 absolute-form，
拆出 scheme/authority/path，**归一化成 origin-form** 存进 IR，并置 `absolute_target=true`。
origin-form 则从 Host 头取 authority、scheme 默认 `http`：[h1_codec.cpp:376-382](src/codec/h1_codec.cpp#L376-L382)。

relay 的分叉：[relay_session.cpp:57-60](src/proxy/relay_session.cpp#L57-L60) —
`absolute_target` → `handle_forward` **直连 URL 的 authority（跳过路由表）**；否则 `route()` 按 Host 路由。

**写请求为什么必须重设 Host**：后端看到的 Host 必须是它自己的，否则虚拟主机路由错位。
你的 forward 强制 `host = authority`：[relay_session.cpp:114-115](src/proxy/relay_session.cpp#L114-L115)。

## 6. CONNECT 方法（隧道）

- CONNECT 不是普通请求：target 是 `host:port`，成功（200）后该连接变成**纯字节隧道**（通常是 TLS）。
- 代理看不到隧道内容，只能原样转发字节。**https 必须走 CONNECT，没有例外**。

你的实现：[relay_session.cpp:47-52](src/proxy/relay_session.cpp#L47-L52) 检测 →
[handle_connect](src/proxy/relay_session.cpp#L176-L207) 解析 host:port →
`200 Connection Established` → [bridge_mode](src/proxy/relay_session.cpp#L209-L232)。
https absolute-form 直接拒绝（400，提示走 CONNECT）：[relay_session.cpp:90-95](src/proxy/relay_session.cpp#L90-L95)。

## 7. Upgrade / 101 WebSocket

- 客户端发 `Upgrade` 头 + `Connection: upgrade` 请求切换协议（WebSocket）。
- 后端回 **101 Switching Protocols** 表示接受 → 之后流量是另一个协议，**不能再按 HTTP 解析**。

你的实现：检测 [is_upgrade_request](src/proxy/relay_session.cpp#L158-L172)；
后端回 101 后 [bridge_mode](src/proxy/relay_session.cpp#L336-L349)（写 101 → 字节桥，且**绝不回连接池**）。

H1-only 的原因：HTTP/3 的 WebSocket 用 RFC 9220 Extended CONNECT，你没实现——面试可以说"这是已知边界"。

## 8. 状态码速记

| 类别 | 含义 | 有无 body | 你项目用到的 |
|---|---|---|---|
| 1xx | 信息（100 Continue / 101 Switching Protocols） | 无 | 101 |
| 2xx | 成功 | 有（HEAD 除外） | 200 |
| 3xx | 重定向 | 304 无 | — |
| 4xx | 客户端错误 | 可有 | 400、404 |
| 5xx | 服务端错误 | 可有 | 502、503 |

你的枚举只有 5 个：[http_message.h:45-51](src/codec/http_message.h#L45-L51)（够用，但可以按上面这张表扩展讲）。

## 9. 一条完整请求的走读（把以上全串起来）

```
curl http://app1.local:8080/x
```
1. H1Codec 读到 `\r\n\r\n` 认定头部完成 [h1_codec.cpp:250-257] → 请求行出 method=GET, path=/x, version=HTTP/1.1 → 无 CL 无 body → `keep_alive=true`
2. `route()` 按 `Host: app1.local` 匹配路由表 [router.cpp:14-31]
3. `UpstreamPool.async_connect`（池复用）→ [async_write_request](src/codec/h1_codec.cpp#L529-L549) 写请求行 + 头 + body
4. 后端回响应 → [read_response_header](src/codec/h1_codec.cpp#L396-L475) → 状态行 200 → 有 CL → `StreamBodySource`
5. 状态行版本用**客户端版本**重写（`client_version_`）[relay_session.cpp:326-331]
6. 写回客户端 → `finish_backend`（后端 keep_alive 则回池）→ `after_client_response`（客户端 keep_alive 则回 request_phase 等下一个请求，否则 teardown）

## 10. 你只需要背住的三件事

1. **body 定界是命门**：CL / chunked / EOF 三种；1xx、204、304、HEAD 无 body；判定顺序不能错。
2. **keep-alive 由版本 + Connection 头决定**，它决定"这条连接还能不能再服务一个请求"，直接驱动相位机回环。
3. **代理的职责边界**：转发语义、剥离 hop-by-hop、重设 Host——除此之外不改内容。
   （CONNECT / Upgrade 是"改不了内容"的两个特例，只能隧道。）
