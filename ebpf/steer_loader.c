// steer_loader.c — verify classic-BPF reuseport steering (Phase 2b).
//
// Attaches a SO_ATTACH_REUSEPORT_CBPF filter that returns the QUIC routing
// byte (skb[8+1] = UDP(8) + DCID[0]; the packet view starts at the UDP
// header) as the reuseport group
// index, then injects probes and counts per-socket delivery.
//
// Usage: ./steer_loader [port]   (default 9477)
#include <linux/filter.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/in.h>

#define N_WORKERS 4

static int make_group_socket(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("bind"); exit(1);
    }
    return fd;
}

static void send_probe(int out_fd, __u8 routing_byte, int port) {
    __u8 pkt[16] = { 0x43, routing_byte, 0x11, 0x22, 0x33, 0x44,
                     0x55, 0x66, 0x77, 0x88, 1, 2, 3, 4, 5, 6 };
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sendto(out_fd, pkt, sizeof pkt, 0, (struct sockaddr *)&dst, sizeof dst);
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 9477;
    int fds[N_WORKERS] = {0};
    for (int i = 0; i < N_WORKERS; ++i)
        fds[i] = make_group_socket(port);

    /* CBPF: A = skb[29] (IP 20 + UDP 8 + DCID[0]); return A = socket index.
       The kernel clamps out-of-range returns to its hash fallback. */
    struct sock_filter code[] = {
        { BPF_LD | BPF_B | BPF_ABS, 0, 0, 8 + 1 },  /* UDP(8) + DCID[0] */
        { BPF_RET | BPF_A,          0, 0, 0 },
    };
    struct sock_fprog fprog = { .len = 2, .filter = code };
    if (setsockopt(fds[0], SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
                   &fprog, sizeof fprog) < 0) {
        perror("SO_ATTACH_REUSEPORT_CBPF"); return 1;
    }
    printf("attached CBPF steering to %d sockets on port %d\n", N_WORKERS, port);

    int out_fd = socket(AF_INET, SOCK_DGRAM, 0);
    for (int rb = 0; rb < N_WORKERS; ++rb)
        for (int k = 0; k < 5; ++k)
            send_probe(out_fd, (__u8)rb, port);
    usleep(200 * 1000);

    int counts[N_WORKERS] = {0};
    for (int i = 0; i < N_WORKERS; ++i) {
        struct pollfd pfd = { .fd = fds[i], .events = POLLIN };
        while (poll(&pfd, 1, 100) == 1) {
            __u8 buf[2048];
            ssize_t n = recv(fds[i], buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0) break;
            ++counts[i];
        }
        printf("socket %d (worker %d): %d packets\n", i, i, counts[i]);
    }

    int ok = 1;
    for (int i = 0; i < N_WORKERS; ++i)
        if (counts[i] != 5) { ok = 0;
            printf("FAIL: expected 5 packets on socket %d\n", i); }
    printf(ok ? "STEERING VERIFIED\n" : "STEERING MISMATCH\n");
    return ok ? 0 : 1;
}
