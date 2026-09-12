// quic_steer.bpf.c — SK_REUSEPORT steering for the QUIC proxy (Phase 2b).
//
// Attached via SO_ATTACH_REUSEPORT_EBPF to a group of N UDP sockets bound to
// the same QUIC port (one per worker).  The BPF program parses the QUIC
// header, derives the owning worker from the routing byte (Phase 2a:
// SCID[0] = worker index), and calls bpf_sk_select_reuseport() to hand the
// packet directly to that worker's socket — no user-space ingress thread.
//
// Only what the verifier needs: every packet read is bounds-checked, no
// loops, no unaligned access.  IPv4 only in this prototype (v6: 40-byte IP).

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define N_WORKERS   4
#define SCID_LEN    8   /* must match the proxy's kServerCidLen */

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, N_WORKERS);
    __type(key, __u32);
    __type(value, __u32);
} reuseport_map SEC(".maps");

SEC("sk_reuseport")
int quic_steer(struct sk_reuseport_md *md)
{
    __u8 *p   = md->data;
    __u8 *end = md->data_end;

    /* IPv4, IHL>=5 */
    if (p + 20 > end)
        return SK_DROP;
    if ((p[0] >> 4) != 4 || (p[0] & 0x0f) < 5)
        return SK_DROP;
    if (p[9] != IPPROTO_UDP)
        return SK_DROP;

    __u8 *q = p + (p[0] & 0x0f) * 4 + 8;   /* QUIC first byte */
    if (q + 1 + SCID_LEN > end)
        return SK_DROP;

    __u8 b0 = q[0];
    __u8 rb = 0xff, h = 0;
    bpf_printk("steer: b0=%u q6=%u q7=%u", b0, q[6], q[7]);

    if (!(b0 & 0x80)) {
        /* Short header: DCID = fixed SCID_LEN bytes at q+1. */
        rb = q[1];
        h  = q[1] + q[2];
    } else if (q[1] | q[2] | q[3] | q[4]) {
        /* Long header with a real version (not VN): DCIL at q[5], DCID next. */
        __u8 dcil = q[5];
        if (dcil >= 1 && dcil <= 20 && q + 6 + dcil <= end) {
            rb = q[6];
            h  = q[6] + dcil;
        }
    }
    __u32 idx = (rb < N_WORKERS) ? rb : (__u32)(h % N_WORKERS);
    /* NOTE: currently the helper fails at runtime in the Docker Desktop VM
       (all probes hash-fallback — see docs/design-multi-ingress.md §2b
       status).  Keep for debugging on a real Linux host. */
    return bpf_sk_select_reuseport(md, &reuseport_map, &idx, 0);
}

char _license[] SEC("license") = "GPL";
