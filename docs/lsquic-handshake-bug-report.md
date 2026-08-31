# Bug report draft: lsquic HTTP/3 server handshake fails with ngtcp2/curl

> （issue #680 的初版根因（SCID 不一致 / 20 字节 DCID）经插桩调查被推翻——
> 那是把 Retry 包的 SCID 误当成 Initial 的。真实原因是下面三条独立的 TLS/QUIC 缺陷。）

## Title

HTTP/3 server handshake fails with ngtcp2/curl: no-SNI CERT_CB_ERROR, unpadded Initial, and TLS never completing the ClientHello

## Body

### Summary
A stock lsquic HTTP/3 server (v4.7.0 and v4.9.4, both built from source) fails to
complete a QUIC handshake with **ngtcp2/curl**, while lsquic's own client completes
fine. Instrumented investigation (deterministic SCID generator, per-call-site
markers, `SSL_do_handshake` tracing) shows the failure is **not** a SCID/DCID-length
issue — that earlier reading was a misattribution. There are three reported
defects.

### Update (verified fix — defects 1 & 2 only, defect 3 was a symptom)
Both defects are fixed by a two-hunk patch
(`third_party/patches/lsquic-4.7.0-http3-interop-a-b.patch`):
1. `iquic_lookup_cert`: fall back to the default cert when no SNI (don't return 0).
2. Re-enable the RFC 9000 §14.1 Initial padding in `lsquic_mini_conn_ietf.c`.

With both applied, the handshake completes and the full H3→H1 proxy path serves
curl on BOTH `https://localhost:PORT/` (SNI) and `https://127.0.0.1:PORT/` (no SNI):
`curl -k --http3-only` → 200 OK.

Note: "defect 3" (SSL_do_handshake WANT_READ forever) was **not** an independent
bug — it is a downstream symptom of defect 2: the unpadded Initial is dropped by
the strict client, so the server never receives the client's Handshake and its
TLS waits forever for input. Once the Initial is padded, the handshake completes.

### Environment
- lsquic 4.7.0 and 4.9.4 (built from source, same repro).
- macOS; loopback UDP.
- Client: Homebrew curl 8.18.0 (ngtcp2 1.19.0, nghttp3 1.14.0), `curl -k --http3-only`.
- Server: a minimal standalone harness on the lsquic server engine API
  (`examples/lsquic_h3_server_min.cpp`, lsquic + BoringSSL only).

### 1. No SNI → CERT_CB_ERROR
Connecting by **IP** (curl to `127.0.0.1` sends no SNI, RFC 6066) makes
`iquic_lookup_cert()` in `lsquic_enc_sess_ietf.c` return 0 in HTTP/3 mode →
BoringSSL aborts with `error:1000007e:SSL routines:OPENSSL_internal:CERT_CB_ERROR`.
Connecting by **hostname** (SNI present) clears this error. lsquic's own client
always sends SNI even for IPs, which is why lsquic↔lsquic works.
- Repro: `curl -k --http3-only https://127.0.0.1:PORT/`

### 2. Ack-eliciting Initial not padded to 1200 bytes (RFC 9000 §14.1)
The server answers the 1200-byte client Initial with a **~60-byte** Initial. The
padding in `lsquic_mini_conn_ietf.c` (`ietf_mini_conn_ci_next_packet_to_send`) is
commented out ("do not pad INIT packet only, instead pad the coalesced later") and
the deferred "coalesced later" padding never happens, so strict clients (ngtcp2)
drop the undersized datagram. Forcing the padding makes the Initial 1255 bytes
(verified).
- Repro: `curl -k --http3-only https://localhost:PORT/` (isolates this from #1)

### 3. Server TLS never completes the ClientHello
Even with SNI present and padding forced, the handshake still fails:
`SSL_do_handshake` returns `WANT_READ` forever after ~143 bytes of ClientHello are
fed, so the **ServerHello is never generated** and the server only sends ACK-only
Initials. Likely a BoringSSL QUIC-mode / CRYPTO-feed issue with the
OpenSSL-generated ClientHello; needs a maintainer to look at the enc-session
handshake path.

### Harness
`examples/lsquic_h3_server_min.cpp` — standalone (lsquic + BoringSSL only), in the
reverse-proxy repo but independent of it. Build `cmake --build build --target
lsquic_h3_min`, run, then the two curl commands above.

Needs any self-signed cert/key (argv[2]/argv[3]; default `certs/`):
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"
./lsquic_h3_server_min 8443 cert.pem key.pem
```

### Notes / fix direction
- Defects 1 and 2 are clearly fixable: fall back to a default cert when no SNI,
  and re-enable the Initial padding. Defect 3 needs investigation of the TLS
  CRYPTO feed.
- Earlier in this thread the failure was reported as "server Initial SCID ≠
  registered SCID with a 20-byte client DCID". That was wrong: the [WIRE] value
  was the **Retry packet's** SCID (SREJ fires when the stalled TLS/TP handshake
  leaves `IMC_HAVE_TP` unset), and the 20-byte DCID is a red herring (curl happens
  to use 20-byte DCIDs *and* OpenSSL *and* no-SNI-on-IP, all differing from
  lsquic's own client).

---

# Filing instructions

## Edit the existing issue (recommended, keeps the discussion)
1. Open https://github.com/litespeedtech/lsquic/issues/680.
2. Click **"Edit"** (⋯ menu) → change the title to the one above.
3. Replace the body with the text above.
4. Update the attached `lsquic_h3_server_min.cpp` (the revised version) if you
   re-attach it.

## Or close #680 and open a new one
1. Close #680 (comment: "superseded by the corrected investigation below; the
   earlier root cause was a misattribution").
2. New issue → paste the title + body above → attach the cpp.

## `gh` CLI alternative (if installed + `gh auth login`)
```bash
gh issue create --repo litespeedtech/lsquic \
  --title "HTTP/3 server handshake fails with ngtcp2/curl: no-SNI CERT_CB_ERROR, unpadded Initial, and TLS never completing the ClientHello" \
  --body-file docs/lsquic-handshake-bug-report.md
```
