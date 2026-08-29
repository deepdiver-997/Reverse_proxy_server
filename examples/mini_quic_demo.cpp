// examples/mini_quic_demo.cpp
//
// 一个迷你"QUIC 引擎"——砍掉加密/拥塞/流控，只保留 lsquic 的接口骨架，
// 用来把 lsquic 的驱动模型彻底看清。
//
// 与真实 lsquic 的对应关系：
//   mini_engine_t              <-> lsquic_engine_t
//   mini_conn_t                <-> lsquic_conn_t        (引擎持有/管理, 你只有句柄)
//   mini_conn_ctx_t            <-> lsquic_conn_ctx_t    (应用持有, 库原样存原样还)
//   mini_stream_t              <-> lsquic_stream_t
//   mini_stream_ctx_t          <-> lsquic_stream_ctx_t
//   mini_stream_if             <-> lsquic_stream_if     (函数指针表 = 虚方法表, self=this)
//   mini_engine_packet_in      <-> lsquic_engine_packet_in
//   mini_engine_process_conns  <-> lsquic_engine_process_conns
//   mini_stream_wantread       <-> lsquic_stream_wantread (电平信号)
//   mini_stream_read/write     <-> lsquic_stream_read/write
//   on_packets_out             <-> ea_packets_out        (引擎回调你, 同步发包)
//
// 核心认知：连接(conn) 和 流(stream) 是两个层级，不是一一对应。
//   一条连接 = 一条安全管道（握手/加密/CID/路径/拥塞）；
//   连接里可以开任意多条流 = 多个独立的可靠字节流（一个请求一条）。
//   一个 QUIC 包能同时携带多条流的 STREAM 帧 —— outbox 就是演示这点。
//
// 假包格式: [4 字节 DCID][1 字节 stream_id][1 字节 type][payload]
//   type = 'D' 携带流数据, 'F' 表示该流 FIN
//
// 编译运行:
//   clang++ -std=c++20 examples/mini_quic_demo.cpp -o /tmp/mini_quic_demo
//   /tmp/mini_quic_demo

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// 不透明上下文：真实 lsquic 用 struct lsquic_conn_ctx {} / lsquic_stream_ctx {}
// 直接以 void* 展示"库不碰内容、原样存原样还"。
using mini_conn_ctx_t   = void;
using mini_stream_ctx_t = void;
//
// [Q] 为什么引擎要单独给 ctx 指针，直接把 mini_conn_t/mini_stream_t 句柄传过来、
//     让 ctx 字段在句柄内部不就行了？
// [A] 在真实 lsquic 里，lsquic_conn_t / lsquic_stream_t 是【不透明类型】：结构体
//     定义藏在库的 .c 里，应用只有指针、看不到任何字段，所以"句柄内部放 ctx"在
//     真实 API 里做不到——库通过 get/set（lsquic_conn_get_ctx）或回调形参把 ctx
//     还给你。本 demo 为了让教学可见才把结构体摊开、ctx 做成可见字段；但为了对齐
//     lsquic 的形状，回调仍单独传 ctx。这样也演示了"库不管你的类型，只管帮你保管
//     指针"的 C userdata 模式。

struct mini_conn_t;
struct mini_stream_t;

// ═══ 回调表：等价于 lsquic_stream_if ═══
struct mini_stream_if {
    // 新连接。返回 conn ctx —— 引擎存下来，之后所有回调原样还给你。
    mini_conn_ctx_t* (*on_new_conn)(void* if_ctx, mini_conn_t* conn);
    // 连接关闭。应用在这里释放它自己的 conn ctx（生命周期归应用管）。
    void (*on_conn_closed)(mini_conn_t* conn);
    // 新流。返回 stream ctx（与 conn ctx 是不同对象，不是同一个）。
    mini_stream_ctx_t* (*on_new_stream)(void* if_ctx, mini_stream_t* s);
    // 流可读（want_read 置位且有数据时触发）。
    void (*on_read)(mini_stream_t* s, mini_stream_ctx_t* ctx);
    // 发包回调：引擎把要发的包交给你，期望你在返回前处理完（同步）。
    int (*on_packets_out)(void* if_ctx, const std::string& dcid,
                          const std::vector<uint8_t>& pkt);
};

// ═══ 连接：等价于 lsquic_conn_t（引擎私有对象） ═══
struct mini_conn_t {
    std::string dcid;                                        // 连接标识（真实里服务端签发 SCID）
    mini_conn_ctx_t* ctx = nullptr;                          // <-> lsquic_conn_get_ctx
    bool closed = false;
    // ★ 一条连接 = 多条流。多路复用就发生在这里。
    std::unordered_map<uint8_t, std::unique_ptr<mini_stream_t>> streams;
    std::vector<uint8_t> outbox;                             // 待发包（可能含多条流的帧）
};

// ═══ 流：等价于 lsquic_stream_t ═══
struct mini_stream_t {
    mini_conn_t* conn = nullptr;                             // 属于哪条连接
    uint8_t sid = 0;                                         // <-> lsquic_stream_id
    mini_stream_ctx_t* ctx = nullptr;                        // <-> lsquic_stream_get_ctx
    bool want_read = false;                                  // <-> lsquic_stream_wantread(电平)
    std::string buf;                                         // 收到的流数据
    bool fin = false;
};

// ═══ 引擎：等价于 lsquic_engine_t ═══
struct mini_engine_t {
    std::unordered_map<std::string, std::unique_ptr<mini_conn_t>> conns; // conns_hash
    const mini_stream_if* iface = nullptr;
    void* if_ctx = nullptr;                                  // <-> ea_stream_if_ctx
    // [A] if_ctx = "回调表的 this"。一套回调函数可以被多个引擎实例共用，
    //     靠 if_ctx 区分"这次回调属于哪个引擎/listener"。真实代码里
    //     ea_stream_if_ctx = this（QuicTransportListener*），回调里 cast 回来。
    //     它和 conn_ctx（每连接）、stream_ctx（每流）是三个层级：
    //     if_ctx 引擎级(1)  <->  conn_ctx 连接级(N)  <->  stream_ctx 流级(N×M)
};

// ── 流读：<-> lsquic_stream_read ──
// 返回读取字节数；0 = EOF；-1 且 errno=EWOULDBLOCK 表示暂无数据。
ssize_t mini_stream_read(mini_stream_t* s, void* buf, size_t len) {
    if (s->buf.empty()) {
        if (s->fin)
            return 0;                                        // EOF
        errno = EWOULDBLOCK;
        return -1;
    }
    size_t n = std::min(len, s->buf.size());
    std::memcpy(buf, s->buf.data(), n);
    s->buf.erase(0, n);
    return (ssize_t)n;
}

// ── 流写：<-> lsquic_stream_write ──
// 简化版：收进所属连接的 outbox（真实 lsquic 会打包 + 直接调 on_packets_out）。
// 注意：多条流的写都汇入同一个 outbox → 一个包承载多条流的帧 = 多路复用。
ssize_t mini_stream_write(mini_stream_t* s, const char* data, size_t len) {
    s->conn->outbox.insert(s->conn->outbox.end(), data, data + len);
    return (ssize_t)len;
}

// ── wantread：<-> lsquic_stream_wantread（电平信号，返回旧值） ──
int mini_stream_wantread(mini_stream_t* s, int want) {
    int prev = s->want_read ? 1 : 0;
    s->want_read = (want != 0);
    return prev;
}

// ── 跑可执行连接：<-> lsquic_engine_process_conns ──
// 由应用在"喂完包后"和"定时器到点"时调用。
// 真实 lsquic 不遍历所有连接，而是维护一个 tickable 队列（只有"有活干"的连接在里面）；
// 这里为教学简单起见直接遍历 + 条件过滤，效果等价。
void mini_engine_process_conns(mini_engine_t* eng) {
    // ① 跑 tickable 流：有缓冲数据且 want_read → on_read
    for (auto& [dcid, c] : eng->conns)
        for (auto& [sid, s] : c->streams)
            if (s->want_read && !s->buf.empty()) {
                std::printf("  [engine] process_conns: tick conn %s sid=%u (%zu bytes queued)\n",
                            dcid.c_str(), sid, s->buf.size());
                eng->iface->on_read(s.get(), s->ctx);
            }
    // ② flush 待发包（同步交给应用）
    for (auto& [dcid, c] : eng->conns) {
        if (!c->outbox.empty()) {
            eng->iface->on_packets_out(eng->if_ctx, dcid, c->outbox);
            c->outbox.clear();
        }
    }
}

// ── 收包：<-> lsquic_engine_packet_in ──
// 同步处理：解出 DCID → 查连接（命中/新建）→ 查流（命中/新建）→ 分发回调 → flush 输出。
int mini_engine_packet_in(mini_engine_t* eng, const uint8_t* data, size_t len,
                          const char* peer) {
    if (len < 6)
        return -1;
    std::string dcid(reinterpret_cast<const char*>(data), 4);
    uint8_t sid = data[4];
    uint8_t type = data[5];
    std::printf("[engine] packet_in: dcid=%.4s sid=%u type=%c peer=%s\n",
                dcid.c_str(), sid, type, peer);

    // ── ① 查/建连接：只靠 CID，不靠 peer {ip,port} ──
    auto it = eng->conns.find(dcid);
    mini_conn_t* conn = nullptr;
    if (it != eng->conns.end()) {
        conn = it->second.get();
        std::printf("  [engine] found existing connection by CID\n");
    } else {
        auto c = std::make_unique<mini_conn_t>();
        c->dcid = dcid;
        conn = c.get();
        std::printf("  [engine] NEW connection by CID (peer %s 只作路径, 不参与解复用)\n", peer);
        conn->ctx = eng->iface->on_new_conn(eng->if_ctx, conn);  // 应用返回 conn ctx
        eng->conns.emplace(dcid, std::move(c));
    }

    // ── ② 查/建流：连接内部按 stream_id 区分 ──
    auto sit = conn->streams.find(sid);
    mini_stream_t* s = nullptr;
    if (sit != conn->streams.end()) {
        s = sit->second.get();
    } else {
        auto ns = std::make_unique<mini_stream_t>();
        ns->conn = conn;
        ns->sid = sid;
        s = ns.get();
        std::printf("  [engine] NEW stream sid=%u on conn %s (连接复用, 流按需开)\n",
                    sid, dcid.c_str());
        s->ctx = eng->iface->on_new_stream(eng->if_ctx, s);     // 应用返回 stream ctx
        conn->streams.emplace(sid, std::move(ns));
    }

    // ── ③ 数据/结束标志投递给这条流 ──
    if (type == 'D' && len > 6) {
        s->buf.append(reinterpret_cast<const char*>(data + 6), len - 6);
        std::printf("  [engine] conn %s sid=%u now has %zu bytes (want_read=%d)\n",
                    dcid.c_str(), sid, s->buf.size(), s->want_read ? 1 : 0);
        if (s->want_read)                       // on_read 可在 packet_in 里直接触发
            eng->iface->on_read(s, s->ctx);
    } else if (type == 'F') {
        s->fin = true;
        std::printf("  [engine] FIN on conn %s sid=%u\n", dcid.c_str(), sid);
        if (s->want_read)
            eng->iface->on_read(s, s->ctx);
    }

    mini_engine_process_conns(eng);             // 喂完包后跑一下引擎
    return 0;
}

// ── 关连接：<-> lsquic_conn_close（会带走它上面的所有流） ──
void mini_conn_close(mini_engine_t* eng, mini_conn_t* conn) {
    if (conn->closed)
        return;
    conn->closed = true;
    eng->iface->on_conn_closed(conn);           // 应用在此释放它自己的 ctx
    eng->conns.erase(conn->dcid);
}

// ═══════════════════════════════════════════════════════════
// 应用侧：实现回调表 + 拥有 session/stream 对象
//  ══ 关键：conn_ctx 是 AppSession（同 QuicTransportSession），
//     stream_ctx 是 AppStream（同 QuicTransportStream）。
//     两者是不同的对象 —— 不是同一个 ctx。
// ═══════════════════════════════════════════════════════════

struct AppSession {   // 等价于 QuicTransportSession
    std::string peer;
    std::string received;                       // 汇总该连接收到的所有流的数据
};

struct AppStream {    // 等价于 QuicTransportStream
    AppSession* session = nullptr;              // 流持有所属连接的 session 引用
};

mini_conn_ctx_t* app_on_new_conn(void* /*if_ctx*/, mini_conn_t* conn) {
    // [A] 为什么是"我们返回"：因为库不知道你的应用类型。库给你一个 void* 槽位，
    //     你在回调里 new 出自己的 C++ 对象（AppSession，真实代码里是
    //     QuicTransportSession）返回给库；库存起来、之后所有回调原样还给你。
    //     于是"应用对象"随连接而存在、由你负责释放（on_conn_closed 里 delete）——
    //     生命周期归应用，库只管保管指针，互不越界。
    auto* sess = new AppSession;
    std::printf("[app]   on_new_conn: new session %p for conn %p\n",
                (void*)sess, (void*)conn);
    return sess;
}

void app_on_conn_closed(mini_conn_t* conn) {
    auto* sess = static_cast<AppSession*>(conn->ctx);
    std::printf("[app]   on_conn_closed: session %p got \"%s\" → freeing %zu stream ctx(s) + session\n",
                (void*)sess, sess->received.c_str(), conn->streams.size());
    for (auto& [sid, s] : conn->streams) {      // 释放每条流的 ctx
        delete static_cast<AppStream*>(s->ctx);
        s->ctx = nullptr;
    }
    delete sess;                                // 再释放连接 ctx
    conn->ctx = nullptr;
}

mini_stream_ctx_t* app_on_new_stream(void* /*if_ctx*/, mini_stream_t* s) {
    auto* st = new AppStream;
    st->session = static_cast<AppSession*>(s->conn->ctx);   // 连到所属连接的 session
    std::printf("[app]   on_new_stream: new stream ctx %p (belongs to session %p)\n",
                (void*)st, (void*)st->session);
    return st;
}

void app_on_read(mini_stream_t* s, mini_stream_ctx_t* ctx) {
    auto* st = static_cast<AppStream*>(ctx);
    char buf[64];
    ssize_t n;
    while ((n = mini_stream_read(s, buf, sizeof(buf))) > 0) {
        st->session->received.append(buf, (size_t)n);
        std::printf("[app]   on_read(conn %s, sid=%u): +%zd → session total \"%s\"\n",
                    s->conn->dcid.c_str(), s->sid, n, st->session->received.c_str());
    }
    if (s->fin && s->buf.empty())
        std::printf("[app]   on_read(conn %s, sid=%u): EOF reached (FIN)\n",
                    s->conn->dcid.c_str(), s->sid);
    mini_stream_wantread(s, 0);                 // 读空 → 关 want_read（边沿收尾）
    // 回显一发, 演示"读回调里写 → 引擎同步发包"
    std::string echo = "echo:" + st->session->received + "\n";
    mini_stream_write(s, echo.data(), echo.size());
}

int app_on_packets_out(void* /*if_ctx*/, const std::string& dcid,
                       const std::vector<uint8_t>& pkt) {
    std::printf("[app]   packets_out: send %zu bytes → CID %s (同步; 可能含多条流的帧)\n",
                pkt.size(), dcid.c_str());
    return 1;                                   // "全部发成功"
}

int main() {
    mini_engine_t eng;
    static const mini_stream_if iface = {
        .on_new_conn     = app_on_new_conn,
        .on_conn_closed  = app_on_conn_closed,
        .on_new_stream   = app_on_new_stream,
        .on_read         = app_on_read,
        .on_packets_out  = app_on_packets_out,
    };
    eng.iface = &iface;
    eng.if_ctx = &eng;

    const char* peer = "1.2.3.4:9999";          // 所有包都来自同一个 peer

    std::printf("══ 1) 同一连接 ABCD 上开两条流(sid=0,1), 再加另一连接 WXYZ —— 连接≠流, 不一一对应 ══\n");
    const uint8_t p1[] = {'A','B','C','D', 0, 'D', 'h','e','l','l','o'};
    const uint8_t p2[] = {'A','B','C','D', 1, 'D', 'w','o','r','l','d'};
    const uint8_t p3[] = {'W','X','Y','Z', 0, 'D', 'o','t','h','e','r'};
    mini_engine_packet_in(&eng, p1, sizeof(p1), peer);
    mini_engine_packet_in(&eng, p2, sizeof(p2), peer);   // 注意: ABCD 只 on_new_conn 一次, on_new_stream 触发两次
    mini_engine_packet_in(&eng, p3, sizeof(p3), peer);

    std::printf("\n══ 2) 三条流都置位 want_read ══\n");
    auto* c1 = eng.conns["ABCD"].get();
    mini_stream_wantread(c1->streams[0].get(), 1);
    mini_stream_wantread(c1->streams[1].get(), 1);
    mini_stream_wantread(eng.conns["WXYZ"].get()->streams[0].get(), 1);

    std::printf("\n══ 3) 再喂包给 ABCD/sid0 —— packet_in 直接触发它; 其余流在 process_conns 被 tick ══\n");
    const uint8_t p4[] = {'A','B','C','D', 0, 'D', '!','!'};
    mini_engine_packet_in(&eng, p4, sizeof(p4), peer);

    std::printf("\n══ 4) 关掉 ABCD —— 它的两条流一起没了; WXYZ 还在 ══\n");
    mini_conn_close(&eng, c1);
    std::printf("    conns 表剩余 %zu 条; WXYZ/sid0 数据仍完好: \"%s\"\n",
                eng.conns.size(),
                static_cast<AppSession*>(eng.conns["WXYZ"].get()->ctx)->received.c_str());

    return 0;
}
