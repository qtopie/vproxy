//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

struct original_dst {
    __u32 ip[4]; // Support IPv6
    __u32 port;
    __u32 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct original_dst);
} cookie_original_dst SEC(".maps");

// The port vproxy is listening on (host byte order).
// This will be rewritten by the Go loader.
volatile const __u32 proxy_port = 8118;

// The mark used to bypass the proxy.
volatile const __u32 bypass_mark = 0xff;

static __always_inline int skip_bypass(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk = (struct bpf_sock *)ctx->sk;
    if (sk) {
        if (sk->mark == bypass_mark) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_local_ipv4(__u32 ip) {
    // ip is in network byte order
    __u32 host_ip = bpf_ntohl(ip);
    
    // 127.0.0.0/8 (Loopback)
    if ((host_ip & 0xFF000000) == 0x7F000000) return 1;
    // 10.0.0.0/8 (Private)
    if ((host_ip & 0xFF000000) == 0x0A000000) return 1;
    // 172.16.0.0/12 (Private)
    if ((host_ip & 0xFFF00000) == 0xAC100000) return 1;
    // 192.168.0.0/16 (Private)
    if ((host_ip & 0xFFFF0000) == 0xC0A80000) return 1;
    // 169.254.0.0/16 (Link-local)
    if ((host_ip & 0xFFFF0000) == 0xA9FE0000) return 1;
    
    return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
    if (skip_bypass(ctx)) return 1;

    // Store original destination
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct original_dst dst = {
        .family = AF_INET,
        .port = ctx->user_port,
    };
    dst.ip[0] = ctx->user_ip4;
    int err = bpf_map_update_elem(&cookie_original_dst, &cookie, &dst, BPF_ANY);
    bpf_printk("sock4_connect: cookie=%llu dst_ip=%x err=%d\n", cookie, dst.ip[0], err);

    // Bypass local/loopback traffic
    if (is_local_ipv4(ctx->user_ip4)) {
        bpf_printk("sock4_connect: cookie=%llu bypassing local\n", cookie);
        return 1;
    }

    // Rewrite destination for TCP/UDP (External traffic only)
    if (ctx->protocol == IPPROTO_TCP || ctx->protocol == IPPROTO_UDP) {
        ctx->user_ip4 = bpf_htonl(0x7F000001); // 127.0.0.1
        ctx->user_port = bpf_htons(proxy_port);
        bpf_printk("sock4_connect: cookie=%llu redirecting to port %d\n", cookie, proxy_port);
    }

    return 1;
}

SEC("cgroup/connect6")
int sock6_connect(struct bpf_sock_addr *ctx) {
    if (skip_bypass(ctx)) return 1;

    // Store original destination
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct original_dst dst = {
        .family = AF_INET6,
        .port = ctx->user_port,
    };
    __builtin_memcpy(dst.ip, ctx->user_ip6, sizeof(dst.ip));
    bpf_map_update_elem(&cookie_original_dst, &cookie, &dst, BPF_ANY);

    // Bypass IPv6 loopback (::1)
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && 
        ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) {
        return 1;
    }

    // Rewrite destination (Only if it's not local)
    if (ctx->protocol == IPPROTO_TCP || ctx->protocol == IPPROTO_UDP) {
        // Redirect to IPv4 loopback for the proxy (dual-stack)
        // or stay in IPv6 loopback if the proxy supports it.
        // For simplicity, redirect to IPv6 loopback ::1
        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = 0;
        ctx->user_ip6[3] = bpf_htonl(1);
        ctx->user_port = bpf_htons(proxy_port);
    }

    return 1;
}
