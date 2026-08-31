# RelaySession 相位机

> 对应代码：`src/proxy/relay_session.{h,cpp}`。ADR-7 的实现，本文是展开。

## 一句话

`RelaySession` 是代理的核心状态机：**一条客户端连接（TCP 连接或 QUIC 流）↔ 一个 HTTP 交换序列**。它不持有线程、不持有 socket——是**纯回调驱动的相位机**：每个相位发起一个异步操作，操作完成时回调驱动进入下一相位。

> **它不是函数调用链**。每一个 `async_*` 调用立即返回，真正的工作发生在回调里。每个回调捕获 `[this, self]`（`self = shared_from_this()`），保证状态机在做异步操作期间存活。

## 相位图

```
                     ┌──────────────────────────────────────────┐
                     │            REQUEST 相位                   │
                     │  async_parse_request(client)             │
                     │  等下一个请求（keep-alive 循环回到这里）     │
                     └──────┬─────────────────────┬──────────────┘
                            │ parse 成功           │ EOF/解析错误
          ┌─────────────────┼─────────────┐        ▼
          │                 │             │      TEARDOWN（终态）
          ▼                 ▼             ▼
      [CONNECT]        [absolute-form]  [普通请求]
      handle_connect    handle_forward  router_->route → pool 连接
          │                 │             │
          └─────────────────┴──────┬──────┘
                                   ▼
                              USE_BACKEND
                          后端连上，存 pending_head/body
                                   │
                                   ▼
                          send_backend_request
                          写请求到后端；失败且池连接陈旧 → 重试一次
                                   │ 成功
                                   ▼
                    ┌──────── RESPONSE 相位 ────────┐
                    │ async_parse_response(backend) │
                    └──────┬───────────────┬────────┘
                           │               │
                  101 Upgrade          普通响应
                           │               │
                           ▼               ▼
                    BRIDGE_MODE     async_write_response(client)
                  双 pump 字节桥        │ 写完
                           │          ┌──────────────┐
                           │          ▼              ▼
                           │   finish_backend    after_client_response
                           │   (回池 or 关闭)     决定：keep-alive? draining?
                           ▼          │              │
                     (EOF→teardown)   │              ├─ 普通 H1 keep-alive → REQUEST 相位（循环）
                                      │              ├─ draining_（停服）→ 优雅关闭
                                      │              └─ 否则 → TEARDOWN
                                      ▼
                                 TEARDOWN（终态）
```

## 逐相位拆解

### 1. Request 相位（`request_phase`，relay_session.cpp:22）——起点，也是 keep-alive 循环点

```cpp
void RelaySession::request_phase() {
    idle_waiting_ = true;                     // 只挂一个读，停服时 FIN 安全
    client_codec_->async_parse_request(client_, [this, self](ec, head, body, keep_alive){
        if (ec) { teardown(); return; }       // 对端关闭或坏请求 → 终态
        client_keep_alive_ = keep_alive;
        // 分派三岔路：
        if (head.method == "CONNECT")   handle_connect(head);          // 隧道
        else if (head.absolute_target)  handle_forward(head, body);    // 正向代理
        else { router_->route(head) → pool_->async_connect(...) → use_backend(...); } // 反向
    });
}
```

解析完请求头后按目标分派：
- **CONNECT** → 直连目标，进隧道（绕过路由表）。
- **absolute-form**（`GET http://host/path`）→ 正向代理，直连 URL authority。
- **普通** → 路由表找后端，从后端池取/建连接。

### 2. use_backend → 请求转发

```cpp
void use_backend(ec, upstream, endpoint, from_pool, head, body) {
    backend_ = std::move(upstream);
    backend_codec_ = (endpoint.protocol == QUIC) ? h3_codec_ : h1_codec_;
    //   ^ 关键：后端协议决定用哪个 codec（TCP 后端走 H1，QUIC 上游走 H3）
    pending_head_ = ...; pending_body_ = ...;  // 暂存，为了可能的重试
    send_backend_request(/*retry_allowed=*/true);
}
```

`send_backend_request`（:261）写请求到后端。**失败重试逻辑**（:272）：

```cpp
if (ec) {
    if (retry_allowed && backend_from_pool_ && !pending_body_) {
        reconnect_backend_fresh();   // 池连接可能被后端空闲关闭了，重连一次
        return;
    }
    close_backend(); write_error(502);
}
```

三个条件**同时**满足才重试：允许重试、来自池（可能是陈旧连接）、**无请求体**（请求体可能已部分发出、无法重放）。

### 3. Response 相位（`response_phase`，:306）

```cpp
backend_codec_->async_parse_response(backend_, [this, self](ec, resp, resp_body, backend_keep_alive){
    if (ec) { close_backend(); write_error(502); return; }
    if (request_method_ == "HEAD") resp_body = nullptr;   // HEAD 的 CL 是"将会有"的长度
    resp.version = client_version_;                        // 用客户端版本重写状态行
    if (request_is_upgrade_ && resp.status_code == 101) {
        write 101 → bridge_mode(); return;                 // WebSocket：转字节桥
    }
    client_codec_->async_write_response(client_, resp, resp_body, [..](ec){
        finish_backend(backend_keep_alive);
        after_client_response();                           // 决策点
    });
});
```

### 4. finish_backend（:361）—— 后端连接善后

```cpp
if (keep_alive) pool_->release(endpoint_, backend_);  // 回池，下次复用
else            close_backend();                       // 关闭
```

### 5. after_client_response（:382）—— 相位机决策点

```cpp
void after_client_response() {
    if (draining_) { gracefully_close_client(); return; }  // 停服：优雅关
    if (client_keep_alive_ && !done_) request_phase();     // 循环：下个请求
    else                              teardown();          // 终态
}
```

### 6. Bridge 模式（CONNECT 隧道 / WebSocket 101，:227 / :234）

```cpp
void bridge_mode() {
    pump_bytes(client_, backend_);   // 客户端→后端 的泵
    pump_bytes(backend_, client_);   // 后端→客户端 的泵
}
void pump_bytes(src, dst) {
    src->async_read_some(buf, [..](ec, n){
        if (ec || n == 0) { teardown(); return; }   // 任一侧结束 → 关两边
        dst->async_write_some(buf, [..](ec){
            if (ec) { teardown(); return; }
            pump_bytes(src, dst);                   // 递归续泵
        });
    });
}
```

两个独立"读→写→递归"泵，任一侧 EOF/错误就 `teardown` 关两端。纯字节搬移，**完全绕过 codec**。

### 7. TEARDOWN（:404）—— 终态

```cpp
void teardown() {
    if (done_) return;                 // 幂等
    done_ = true;
    client_->async_shutdown(...);      // 客户端 FIN
    close_backend();                   // 后端关闭/回池已处理
}
```

## 状态变量

| 变量 | 含义 |
|---|---|
| `idle_waiting_` | 在 request_phase 等下一个请求（只挂读、无待写）→ 停服时 FIN 安全 |
| `draining_` | 停服标记：响应完成后不再循环 keep-alive，改优雅关闭 |
| `done_` | 终态标记：teardown 后所有回调 return early |
| `client_keep_alive_` | 客户端请求是否 `Connection: keep-alive` |

## 生命周期（shared_ptr + self）

每个异步操作的回调都捕获 `[this, self]`：
- `self` = `shared_from_this()`，保证状态机在做异步操作期间不被销毁。
- 即使 ProxyCore 只持有弱引用（`live_relays_`），只要有一个回调在途，RelaySession 就活着。
- 终态后 `done_` 短路，最后一个 `self` 释放 → RelaySession 析构 → 客户端流/后端流释放。

## 三个特殊流（都从 Request 相位岔出）

1. **CONNECT**（:176）：解析 `host:port` → `async_connect_fresh`（不走池）→ 写 `200 Connection Established` → bridge_mode。
2. **absolute-form**（:85）：校验 scheme 是 http（https 必须走 CONNECT）→ 直连 authority → use_backend（走同一转发链路）。
3. **WebSocket Upgrade**：正常转发 → 后端回 101 → bridge_mode，且**不把后端连接回池**（`backend_from_pool_ = false`，它是活的隧道）。

## 与优雅关闭的交互

`graceful_close()`（停服时 ProxyCore 从弱引用表调过来，见 design-quic-demux.md §11.5）：
- **空闲**（`idle_waiting_`）→ 立即 `async_shutdown`（FIN）；pending 的 request_phase 读会看到对端 EOF → teardown。
- **在途** → 置 `draining_`，不打断；当前响应完成后 `after_client_response` 看到 `draining_` → `gracefully_close_client`（FIN + drain 到 EOF）而不是循环。

## 实现方式讨论：隐式状态 vs 显式 enum / 跳转表

**现状是"方法即状态"**：`request_phase()` / `response_phase()` / `bridge_mode()` 这些方法本身就是状态的隐式表示——"正在执行哪个回调链"就是当前相位。没有显式 `Phase phase_` 枚举。

**优点**：
- 不可能出现"处于一个没有对应方法的非法状态"——状态和转移逻辑内聚在同一处。
- 每个相位的局部变量是自然的 C++ 局部变量/回调闭包（如 parse 回调闭包捕获 `head`/`body`）。
- 与 asio 事件驱动契合——回调链就是 continuation。

**代价**（我们在优雅关闭里真实踩到）：
- **无法查询"我现在在哪个相位"**——停服逻辑只能靠补 `idle_waiting_` / `draining_` 两个旗标去猜，而不是查 `phase()`。
- 状态转移散落在各回调边界，全貌要靠文档/读代码，编译器不帮你校验。
- 跨切面关注点（停服、超时、限流）需要在多个回调里插旗标 + 检查。

**结论：加显式 `Phase phase_` 枚举 + `goto_phase()`，但不要跳转表注册表。** 理由：

- 对**同步 FSM**（解析器、协议解码器），"状态注册表 + 每个状态的 enter/handle 函数指针"是黄金标准——控制流真的由状态表驱动。
- 但这里是**异步 I/O 状态机**：真正的控制流活在 asio 回调里，状态表只会在回调之上再加一层间接，跳转函数入口与回调 continuation **重复表述同一份控制流**——收益（可读性）被两层跳转抵消。
- 折中且真正解决痛点的做法：`enum class Phase { kRequest, kForward, kResponse, kBridge, kClosed }`，在每次相位切换处 `phase_ = Phase::...`（或 `goto_phase()`），停服/超时逻辑改查 `phase_`，把 `idle_waiting_`/`draining_` 收编成"相位 + 一个 shutdown 标记"。要可视化的状态转移表就 `constexpr` 一张 `from→to` 表做断言/日志，**不必**做成函数指针跳转。

一句话总结：**它是"一条连接上连续 HTTP 交换"的有限状态机**——Request 解析并分派，Response 回写并回收后端，`after_client_response` 决定循环/优雅关/终态；CONNECT / absolute-form / WebSocket 是 Request 岔出的三条支路；一切异步、一切靠 `self` 保活、`done_` 短路收尾。
