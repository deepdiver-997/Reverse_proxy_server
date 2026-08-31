# Bug report draft: lsquic HTTP/3 server handshake fails with ngtcp2/curl (20-byte client DCID)

> （可按原样贴到 GitHub issue，或自行精简/翻译。提交前先跑一遍确认没被他人先报。）

## Title

HTTP/3 server handshake fails with ngtcp2/curl: server's Initial SCID differs from the SCID it registers, so the client's Handshake can't be matched back to the connection

## Body

### Summary
A stock lsquic **server** engine fails to complete a QUIC handshake with **ngtcp2/curl** clients, while lsquic's own client engine completes it fine. **Verified by building both v4.7.0 and the latest v4.9.4 from source and running the same harness + curl: the bug reproduces identically on both.** Root cause is a Connection-ID consistency bug triggered when the client's Initial packet uses a **20-byte DCID** (= `MAX_CID_LEN`): the server emits an Initial whose SCID field differs from the SCID it registers via `ea_new_scids` / `lsquic_engine_add_cid`, so the client's Handshake (which echoes the wire SCID) can't be matched to the mini-connection and is treated as a brand-new connection.

### Environment
- lsquic 4.7.0 (tag `39718e5`, "Release 4.7.0"). Confirmed identical SCID/CID code in `v4.9.4` (only added `es_max_header_sets`, unrelated).
- macOS (but platform-agnostic; loopback UDP).
- Client: Homebrew curl 8.18.0 (ngtcp2 1.19.0, nghttp3 1.14.0), `curl -k --http3-only https://127.0.0.1:8443/`.
- Server: a reverse proxy built on the lsquic server engine API (`LSENG_SERVER | LSENG_HTTP`, TLS 1.3, ALPN h3, `es_scid_len = 8`).

### Repro (standalone harness — 30s)
A minimal standalone lsquic server is included for you to reproduce directly
(in the open-source reverse-proxy repo, but it does **not** depend on it — only
lsquic + BoringSSL): `examples/lsquic_h3_server_min.cpp`. Build with
`cmake --build build --target lsquic_h3_min`, then:

```console
$ ./build/lsquic_h3_min 18455          # from the repo root (reads certs/)
$ curl -k --http3-only https://127.0.0.1:18455/
```

Harness output (this is the entire bug in three lines):

```
[REG]  ea_new_scids SCID len=8 hex=c5decb585547a885    <-- SCID registered
[WIRE] outbound Initial SCID len=8 hex=93573d66575c5e03 <-- SCID actually on the wire
# ...curl exit=7, on_new_conn NEVER fires...
```

The harness logs `[REG]` (SCID via `ea_new_scids`) and `[WIRE]` (SCID parsed from
the outbound Initial packet) for each new connection. The client echoes `[WIRE]`
as its Handshake DCID; the server (and any external CID router) can only find
`[REG]` — mismatch → mismatch → the Handshake can't be matched to the mini-conn
and is treated as a brand-new connection.

### Byte-level evidence (from the standalone harness / proxy)
- `ea_new_scids` reports SCID `c5decb585547a885` (8 bytes).
- The outbound Initial carries SCID `93573d66575c5e03` (8 bytes) — what the client echoes.
- These differ → server sends an Initial whose SCID it never registered; the
  client's Handshake DCID can't be matched by `conns_hash` (nor a demux).

### Symptom details (why it never completes)
1. Client Initial: DCID = **20 bytes** (ngtcp2). Server registers SCID X, replies Initial with wire SCID Y (Y ≠ X).
2. Client Handshake: DCID = Y (echoed). Server's `find_or_create_conn()` looks up Y, misses, creates a NEW mini-conn (a second `ea_new_scids`/`get_ssl_ctx` fires), and `on_new_conn` never fires.
3. Interesting confirmation: that *second* mini-conn's SCID **does** match its wire SCID — the mismatch happens only on the 20-byte-original-DCID connection.

### A control that works (isolates the trigger = 20-byte Initial DCID)
lsquic's own client engine (uses an **8-byte** Initial DCID) against the same server completes fine (`on_new_conn` fires, request/response flows). So the server is fine for 8-byte client DCIDs and breaks specifically for ngtcp2's 20-byte one.

### Suggested starting points for the fix
- In the server mini-conn SCID issue path: ensure the SCID carried in the server's Initial packet is the same CID inserted into `conns_hash`/reported via `lsquic_engine_add_cid` (`ea_new_scids`). The 8-byte SCID generation diverges from the registered value specifically when the client's original DCID is 20 bytes.
- Verify `es_scid_len` vs `MAX_CID_LEN` (20) interaction in Initial packet construction.

### Additional info
`examples/lsquic_h3_server_min.cpp` is self-contained (lsquic + BoringSSL only) and can be shared/extracted; full packet captures available on request.

---

# Filing instructions (how to create the issue)

## Option A — GitHub web UI (recommended)
1. Open https://github.com/litespeedtech/lsquic/issues in a logged-in browser.
2. Click the green **"New issue"** button (top-right).
3. Paste the title + body above.
4. Optionally tag `Component: server`, and attach any packet capture.
5. Click **"Submit new issue"**.

## Option B — `gh` CLI (need `gh` installed + `gh auth login`)
```bash
gh issue create --repo litespeedtech/lsquic \
  --title "HTTP/3 server handshake fails with ngtcp2/curl: Initial SCID != registered SCID (20-byte client DCID)" \
  --body-file docs/lsquic-handshake-bug-report.md
```

> Note: the sandbox here cannot create the issue for you — it has no GitHub auth and github.com (web/raw) is unreachable from it, only api.github.com. So filing on the web (or your own `gh`) is the way.