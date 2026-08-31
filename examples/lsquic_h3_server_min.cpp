// lsquic_h3_server_min — MINIMAL standalone lsquic HTTP/3 server harness.
//
// Purpose: reproduce the handshake failures between an lsquic server and
// ngtcp2/curl.  Only depends on lsquic + OpenSSL/BoringSSL — NOT the proxy
// project.
//
// Three independent defects are visible (verified on lsquic 4.7.0 AND 4.9.4,
// both built from source):
//   1. No-SNI → CERT_CB_ERROR.  Connecting by IP (curl to 127.0.0.1 sends no
//      SNI per RFC 6066) makes iquic_lookup_cert() return 0 in HTTP/3 mode →
//      BoringSSL aborts with CERT_CB_ERROR.  Connect by hostname to avoid.
//   2. Ack-eliciting Initial is NOT padded to 1200 bytes (RFC 9000 §14.1): the
//      server answers the 1200-byte client Initial with a ~60-byte Initial
//      (the padding in lsquic_mini_conn_ietf.c is commented out).
//   3. Server TLS never completes the ClientHello: SSL_do_handshake returns
//      WANT_READ forever, no ServerHello is generated, only ACK-only Initials
//      are sent.
//
// It logs the SCID lsquic reports via ea_new_scids ([REG]) and the SCID parsed
// from each outbound long-header packet ([WIRE]).  NOTE: with default settings
// the server may send a Retry packet (SREJ), whose fresh SCID legitimately
// differs from [REG] — that is NOT the Initial's SCID.
//
// Build:   cmake --build build --target lsquic_h3_min
// Run:     ./build/lsquic_h3_min [port]      (default 8443, from repo root)
// Test:    curl -k --http3-only https://127.0.0.1:PORT/   (defect 1)
//          curl -k --http3-only https://localhost:PORT/  (defects 2/3)

#include <lsxpack_header.h>
#include <lsquic.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>

// ── tiny helpers: hex dump, canned response build ────────
static std::string hexstr(const unsigned char* p, size_t n) {
    static const char d[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}

// ── HTTP/3 header-set interface (QPACK decode) ────────────
struct Hset {
    std::array<char, 64 * 1024> buf{};
    struct lsxpack_header xhdr {};
    size_t dec_off = 0;
    bool have_xhdr = false;
};
static void* hsi_create(void*, lsquic_stream_t*, int) { return new Hset(); }
static struct lsxpack_header* hsi_prepare(void* hs_, lsxpack_header* hdr, size_t space) {
    auto* hs = static_cast<Hset*>(hs_);
    if (hdr) return nullptr; // no buffer growth
    if (hs->have_xhdr) hs->dec_off += lsxpack_header_get_dec_size(&hs->xhdr);
    else hs->have_xhdr = true;
    lsxpack_header_prepare_decode(&hs->xhdr, hs->buf.data(), hs->dec_off,
                                  hs->buf.size() - hs->dec_off);
    return &hs->xhdr;
}
static int hsi_process(void*, lsxpack_header*) { return 0; }
static void hsi_discard(void* hs_) { delete static_cast<Hset*>(hs_); }
static const lsquic_hset_if kHsi = {
    .hsi_create_header_set  = hsi_create,
    .hsi_prepare_decode     = hsi_prepare,
    .hsi_process_header     = hsi_process,
    .hsi_discard_header_set = hsi_discard,
};

// ── TLS ───────────────────────────────────────────────────
static struct ssl_ctx_st* server_ssl_ctx = nullptr;
static struct ssl_ctx_st* get_ssl_ctx_cb(void* peer_ctx, const struct sockaddr*) {
    return server_ssl_ctx;
}
static struct ssl_ctx_st* lookup_cert_cb(void* peer_ctx, const struct sockaddr*, const char*) {
    return server_ssl_ctx;
}

// ── per-stream state ──────────────────────────────────────
struct StreamCtx { bool responded = false; };

// Send a canned HTTP/3 "200 handshake-ok" response and FIN the stream.
static void send_response(lsquic_stream_t* s, const char* body, size_t bodylen) {
    const char* names[3] = {":status", "content-type", "content-length"};
    std::string clen = std::to_string(bodylen);
    const char* vals[3] = {"200", "text/plain", clen.c_str()};

    size_t total = 0;
    for (int i = 0; i < 3; ++i) total += std::strlen(names[i]) + std::strlen(vals[i]);
    std::vector<char> nv; nv.reserve(total);
    std::array<lsxpack_header, 3> arr{};
    size_t off = 0;
    for (int i = 0; i < 3; ++i) {
        nv.insert(nv.end(), names[i], names[i] + std::strlen(names[i]));
        nv.insert(nv.end(), vals[i], vals[i] + std::strlen(vals[i]));
        lsxpack_header_set_offset2(&arr[i], nv.data(), off, std::strlen(names[i]),
                                   off + std::strlen(names[i]), std::strlen(vals[i]));
        off += std::strlen(names[i]) + std::strlen(vals[i]);
    }
    lsquic_http_headers_t hs = { 3, arr.data() };
    lsquic_stream_send_headers(s, &hs, 0);
    lsquic_stream_write(s, (const unsigned char*)body, bodylen);
    lsquic_stream_shutdown(s, 1); // FIN
    lsquic_stream_flush(s);
}

// Parse + log the SCID field of an OUTBOUND long-header packet.
// Server->client Initial: [hdr][ver 4B][dcid_len][dcid][scid_len][scid]...
static void dump_wire_scid(const unsigned char* p, size_t len) {
    if (len < 7 || !(p[0] & 0x80)) return;              // need a long header
    size_t pos = 6 + p[5];                              // skip DCID len + DCID
    if (pos >= len) return;
    size_t sclen = p[pos];
    if (sclen > 20 || pos + 1 + sclen > len) return;
    printf("[WIRE] outbound long-header SCID len=%zu hex=%s\n", sclen,
           hexstr(p + pos + 1, sclen).c_str());
    fflush(stdout);
}

// ── lsquic stream interface ───────────────────────────────
static lsquic_conn_ctx_t* on_new_conn(void*, lsquic_conn_t* c) {
    printf("[LOG] on_new_conn — HANDSHAKE COMPLETED (conn=%p)\n", (void*)c);
    fflush(stdout);
    return nullptr; // per-conn ctx unused
}
static void on_conn_closed(lsquic_conn_t*) {
    printf("[LOG] on_conn_closed\n"); fflush(stdout);
}
static lsquic_stream_ctx_t* on_new_stream(void*, lsquic_stream_t* s) {
    auto* sc = new StreamCtx();
    lsquic_stream_set_ctx(s, reinterpret_cast<lsquic_stream_ctx_t*>(sc));
    printf("[LOG] new stream %llu\n", (unsigned long long)lsquic_stream_id(s));
    fflush(stdout);
    return reinterpret_cast<lsquic_stream_ctx_t*>(sc);
}
static void on_read(lsquic_stream_t* s, lsquic_stream_ctx_t* ctx) {
    auto* sc = reinterpret_cast<StreamCtx*>(ctx);
    void* hset = lsquic_stream_get_hset(s);
    if (hset) hsi_discard(hset);                 // request headers arrived
    char buf[2048];
    while (lsquic_stream_read(s, (unsigned char*)buf, sizeof buf) > 0) {}
    if (!sc->responded) {
        sc->responded = true;
        static const char body[] = "handshake-ok";
        send_response(s, body, sizeof body - 1);
        printf("[LOG] responded 200\n"); fflush(stdout);
    }
}
static void on_write(lsquic_stream_t*, lsquic_stream_ctx_t*) {}
static void on_close(lsquic_stream_t*, lsquic_stream_ctx_t* ctx) {
    delete reinterpret_cast<StreamCtx*>(ctx);
}
static void on_reset(lsquic_stream_t*, lsquic_stream_ctx_t*, int) {}
static void on_hsk_done(lsquic_conn_t*, enum lsquic_hsk_status st) {
    printf("[LOG] on_hsk_done status=%d\n", (int)st); fflush(stdout);
}
static const lsquic_stream_if kStreamIf = {
    .on_new_conn    = on_new_conn,
    .on_conn_closed = on_conn_closed,
    .on_new_stream  = on_new_stream,
    .on_read        = on_read,
    .on_write       = on_write,
    .on_close       = on_close,
    .on_reset       = on_reset,
    .on_hsk_done    = on_hsk_done,
};

// ── SCID reporting ────────────────────────────────────────
static void on_new_scids(void*, void**, const lsquic_cid_t* cids, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        printf("[REG] ea_new_scids SCID len=%u hex=%s\n", (unsigned)cids[i].len,
               hexstr(cids[i].buf, cids[i].len).c_str());
    fflush(stdout);
}
static void on_old_scids(void*, void**, const lsquic_cid_t* cids, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        printf("[REG] ea_old_scids SCID len=%u hex=%s\n", (unsigned)cids[i].len,
               hexstr(cids[i].buf, cids[i].len).c_str());
    fflush(stdout);
}

// ── packet out: dump wire SCID, then sendmsg ──────────────
static int packets_out(void* ctx, const lsquic_out_spec* specs, unsigned count) {
    int fd = *(int*)ctx;
    for (unsigned i = 0; i < count; ++i) {
        dump_wire_scid((const unsigned char*)specs[i].iov[0].iov_base,
                       specs[i].iov[0].iov_len);
        struct msghdr h = {};
        h.msg_name = (void*)specs[i].dest_sa;
        h.msg_namelen = specs[i].dest_sa->sa_family == AF_INET
                            ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        h.msg_iov = (struct iovec*)specs[i].iov;
        h.msg_iovlen = specs[i].iovlen;
        sendmsg(fd, &h, 0);
    }
    return (int)count;
}

int main(int argc, char* argv[]) {
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : 8443;
    const char* cert = (argc > 2) ? argv[2] : "certs/cert.pem";
    const char* key  = (argc > 3) ? argv[3] : "certs/key.pem";

    if (lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "lsquic_global_init failed\n"); return 1;
    }

    // TLS 1.3 + H3 ALPN.
    server_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!server_ssl_ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }
    if (SSL_CTX_use_certificate_chain_file(server_ssl_ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(server_ssl_ctx, key, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "cannot load %s / %s\n", cert, key); return 1;
    }
    SSL_CTX_set_min_proto_version(server_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(server_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(server_ssl_ctx, [](SSL*, const unsigned char** o, unsigned char* ol,
        const unsigned char* in, unsigned int inlen, void*) {
        static const unsigned char alpn[] = "\x02h3\x05h3-29";
        return SSL_select_next_proto((unsigned char**)o, ol, in, inlen, alpn,
                                     sizeof(alpn) - 1) == OPENSSL_NPN_NEGOTIATED
               ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
    }, nullptr);

    // UDP socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0) { perror("bind"); return 1; }
    int* pfd = new int(fd);

    // Engine.
    lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_SERVER | LSENG_HTTP);
    settings.es_scid_len = 8;
    lsquic_engine_api api{};
    api.ea_settings         = &settings;
    api.ea_packets_out      = packets_out;
    api.ea_packets_out_ctx  = pfd;              // packets_out reads fd from here
    api.ea_get_ssl_ctx      = get_ssl_ctx_cb;
    api.ea_lookup_cert      = lookup_cert_cb;
    api.ea_stream_if        = &kStreamIf;
    api.ea_stream_if_ctx    = &settings;
    api.ea_hsi_if           = &kHsi;
    api.ea_new_scids        = on_new_scids;
    api.ea_old_scids        = on_old_scids;
    api.ea_cids_update_ctx  = &settings;
    lsquic_engine_t* engine = lsquic_engine_new(LSENG_SERVER | LSENG_HTTP, &api);
    if (!engine) { fprintf(stderr, "engine_new failed\n"); return 1; }

    printf("lsquic %d.%d.%d (es_scid_len=%u) listening on UDP 127.0.0.1:%u\n"
           ">>> curl -k --http3-only https://127.0.0.1:%u/\n",
           LSQUIC_MAJOR_VERSION, LSQUIC_MINOR_VERSION, LSQUIC_PATCH_VERSION,
           settings.es_scid_len, port, port);
    fflush(stdout);

    std::array<char, 65536> buf{};
    for (;;) {
        struct sockaddr_storage peer, local;
        socklen_t pl = sizeof peer, ll = sizeof local;
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        int diff = 0;
        lsquic_engine_earliest_adv_tick(engine, &diff);
        struct timeval tv{};
        if (diff < 0) tv = {0, 0};
        else { tv.tv_sec = diff / 1000; tv.tv_usec = (diff % 1000) * 1000; }
        if (select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(fd, &rfds)) {
            ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0, (struct sockaddr*)&peer, &pl);
            if (n > 0) {
                getsockname(fd, (struct sockaddr*)&local, &ll);
                lsquic_engine_packet_in(engine, (const unsigned char*)buf.data(), n,
                                        (struct sockaddr*)&local, (struct sockaddr*)&peer,
                                        &settings, 0);
            }
        }
        lsquic_engine_process_conns(engine);
    }
    return 0;
}