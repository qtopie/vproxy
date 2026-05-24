//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

/* ── Structs ─────────────────────────────────────────────────── */

/* Original destination saved before rewrite. */
struct original_dst {
	__u32 ip[4]; /* IPv4: ip[0] only (network byte order); IPv6: all 4 words */
	__u32 port;  /* network byte order */
	__u32 family; /* AF_INET or AF_INET6 */
};

/*
 * Key for the UDP original-destination map.
 * We key by {src_port, family} because the proxy receives UDP packets
 * with a known source port (assigned by the kernel before sendmsg fires),
 * allowing O(1) lookup without needing the socket cookie.
 *
 * src_port is in HOST byte order (same as bpf_sock.src_port).
 */
struct udp_orig_key {
	__u16 src_port; /* host byte order */
	__u8  family;   /* AF_INET or AF_INET6 */
	__u8  pad;
};

/*
 * Key for the LPM-TRIE CIDR bypass map.
 * addr is in HOST byte order so that LPM prefix matching is straightforward.
 */
struct lpm_cidr_key {
	__u32 prefixlen;
	__u32 addr; /* host byte order */
};

/* ── Maps ────────────────────────────────────────────────────── */

/*
 * TCP original destination: socket_cookie → original_dst.
 * Written in cgroup/connect4 and cgroup/connect6 for TCP.
 * Read and deleted by the Go tproxy handler after accept().
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct original_dst);
} tcp_orig_dst SEC(".maps");

/*
 * UDP original destination: {src_port, family} → original_dst.
 * Written in:
 *   - cgroup/connect4 / cgroup/connect6 for *connected* UDP (connect() + send())
 *   - cgroup/sendmsg4 / cgroup/sendmsg6 for *unconnected* UDP (sendto())
 * Read and deleted by the Go tproxy handler per received UDP packet.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct udp_orig_key);
	__type(value, struct original_dst);
} udp_orig_dst SEC(".maps");

/*
 * CIDR bypass list (LPM_TRIE).
 * Destinations matching any entry are NOT redirected to the proxy.
 * Populated from Go with private address ranges (127/8, 10/8, etc.).
 * BPF_F_NO_PREALLOC is required for LPM_TRIE.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_cidr_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_bypass_map SEC(".maps");

/*
 * Runtime configuration array.
 * Index 0 → proxy_port  (host byte order, u64)
 * Index 1 → bypass_mark (u64, default 0xff)
 * Index 2 → verbose     (0=off, 1=on)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} config_map SEC(".maps");

/* ── Config helpers ──────────────────────────────────────────── */

#define CFG_PROXY_PORT  0
#define CFG_BYPASS_MARK 1
#define CFG_VERBOSE     2

/* Default values used when config_map lookup fails (should not happen). */
#define DEFAULT_PROXY_PORT  8118
#define DEFAULT_BYPASS_MARK 0xff

static __always_inline __u32 cfg_proxy_port(void) {
	__u32 idx = CFG_PROXY_PORT;
	__u64 *v = bpf_map_lookup_elem(&config_map, &idx);
	return v ? (__u32)*v : DEFAULT_PROXY_PORT;
}

static __always_inline __u32 cfg_bypass_mark(void) {
	__u32 idx = CFG_BYPASS_MARK;
	__u64 *v = bpf_map_lookup_elem(&config_map, &idx);
	return v ? (__u32)*v : DEFAULT_BYPASS_MARK;
}

static __always_inline int cfg_verbose(void) {
	__u32 idx = CFG_VERBOSE;
	__u64 *v = bpf_map_lookup_elem(&config_map, &idx);
	return v ? (int)*v : 0;
}

/* ── Decision helpers ────────────────────────────────────────── */

/* Returns 1 if this socket is vproxy's own upstream connection (skip it). */
static __always_inline int is_bypass_socket(struct bpf_sock_addr *ctx) {
	struct bpf_sock *sk = ctx->sk;
	if (!sk)
		return 0;
	return sk->mark == cfg_bypass_mark();
}

/*
 * IPv4 CIDR bypass lookup.
 * addr_net is in NETWORK byte order (as seen in IP header / bpf_sock_addr).
 */
static __always_inline int is_cidr_bypass_v4(__u32 addr_net) {
	struct lpm_cidr_key k = {
		.prefixlen = 32,
		.addr      = bpf_ntohl(addr_net), /* convert to host byte order */
	};
	return bpf_map_lookup_elem(&cidr_bypass_map, &k) != NULL;
}

/*
 * IPv6 bypass: only skip well-known local ranges.
 * (LPM_TRIE for IPv6 would need a 128-bit key; kept simple for now.)
 *   - ::1        loopback
 *   - fe80::/10  link-local
 *   - fc00::/7   ULA
 */
static __always_inline int is_local_ipv6(__u32 ip6[4]) {
	/* ::1 */
	if (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 &&
	    ip6[3] == bpf_htonl(1))
		return 1;
	/* fe80::/10 */
	if ((bpf_ntohl(ip6[0]) & 0xFFC00000U) == 0xFE800000U)
		return 1;
	/* fc00::/7  (covers fc00:: and fd00::) */
	if ((bpf_ntohl(ip6[0]) & 0xFE000000U) == 0xFC000000U)
		return 1;
	return 0;
}

/* ── cgroup/connect4  (IPv4 TCP + connected UDP) ─────────────── */

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
	if (is_bypass_socket(ctx))
		return 1;
	if (is_cidr_bypass_v4(ctx->user_ip4))
		return 1;

	__u32 proxy_port = cfg_proxy_port();

	struct original_dst dst = {
		.family = AF_INET,
		.port   = ctx->user_port, /* network byte order */
	};
	dst.ip[0] = ctx->user_ip4;

	if (ctx->protocol == IPPROTO_TCP) {
		__u64 cookie = bpf_get_socket_cookie(ctx);
		bpf_map_update_elem(&tcp_orig_dst, &cookie, &dst, BPF_ANY);
		if (cfg_verbose())
			bpf_printk("[vproxy] connect4/tcp cookie=%llu dst=%x:%d",
			           cookie, bpf_ntohl(dst.ip[0]),
			           bpf_ntohs((__u16)dst.port));
	} else if (ctx->protocol == IPPROTO_UDP) {
		struct udp_orig_key k = {
			.src_port = ctx->sk->src_port, /* host byte order */
			.family   = AF_INET,
		};
		bpf_map_update_elem(&udp_orig_dst, &k, &dst, BPF_ANY);
		if (cfg_verbose())
			bpf_printk("[vproxy] connect4/udp sport=%d dst=%x:%d",
			           k.src_port, bpf_ntohl(dst.ip[0]),
			           bpf_ntohs((__u16)dst.port));
	}

	ctx->user_ip4  = bpf_htonl(0x7F000001); /* 127.0.0.1 */
	ctx->user_port = bpf_htons((__u16)proxy_port);
	return 1;
}

/* ── cgroup/sendmsg4  (IPv4 unconnected UDP: sendto / sendmsg) ─ */

SEC("cgroup/sendmsg4")
int sock4_sendmsg(struct bpf_sock_addr *ctx) {
	if (is_bypass_socket(ctx))
		return 1;
	if (is_cidr_bypass_v4(ctx->user_ip4))
		return 1;

	__u32 proxy_port = cfg_proxy_port();

	struct original_dst dst = {
		.family = AF_INET,
		.port   = ctx->user_port,
	};
	dst.ip[0] = ctx->user_ip4;

	struct udp_orig_key k = {
		.src_port = ctx->sk->src_port, /* host byte order */
		.family   = AF_INET,
	};
	bpf_map_update_elem(&udp_orig_dst, &k, &dst, BPF_ANY);

	if (cfg_verbose())
		bpf_printk("[vproxy] sendmsg4 sport=%d dst=%x:%d",
		           k.src_port, bpf_ntohl(dst.ip[0]),
		           bpf_ntohs((__u16)dst.port));

	ctx->user_ip4  = bpf_htonl(0x7F000001);
	ctx->user_port = bpf_htons((__u16)proxy_port);
	return 1;
}

/* ── cgroup/connect6  (IPv6 TCP + connected UDP) ─────────────── */

SEC("cgroup/connect6")
int sock6_connect(struct bpf_sock_addr *ctx) {
	if (is_bypass_socket(ctx))
		return 1;
	if (is_local_ipv6(ctx->user_ip6))
		return 1;

	__u32 proxy_port = cfg_proxy_port();

	struct original_dst dst = {
		.family = AF_INET6,
		.port   = ctx->user_port,
	};
	__builtin_memcpy(dst.ip, ctx->user_ip6, sizeof(dst.ip));

	if (ctx->protocol == IPPROTO_TCP) {
		__u64 cookie = bpf_get_socket_cookie(ctx);
		bpf_map_update_elem(&tcp_orig_dst, &cookie, &dst, BPF_ANY);
		if (cfg_verbose())
			bpf_printk("[vproxy] connect6/tcp cookie=%llu", cookie);
	} else if (ctx->protocol == IPPROTO_UDP) {
		struct udp_orig_key k = {
			.src_port = ctx->sk->src_port,
			.family   = AF_INET6,
		};
		bpf_map_update_elem(&udp_orig_dst, &k, &dst, BPF_ANY);
		if (cfg_verbose())
			bpf_printk("[vproxy] connect6/udp sport=%d", k.src_port);
	}

	/* Redirect to ::1:proxy_port */
	ctx->user_ip6[0] = 0;
	ctx->user_ip6[1] = 0;
	ctx->user_ip6[2] = 0;
	ctx->user_ip6[3] = bpf_htonl(1);
	ctx->user_port   = bpf_htons((__u16)proxy_port);
	return 1;
}

/* ── cgroup/sendmsg6  (IPv6 unconnected UDP: sendto / sendmsg) ─ */

SEC("cgroup/sendmsg6")
int sock6_sendmsg(struct bpf_sock_addr *ctx) {
	if (is_bypass_socket(ctx))
		return 1;
	if (is_local_ipv6(ctx->user_ip6))
		return 1;

	__u32 proxy_port = cfg_proxy_port();

	struct original_dst dst = {
		.family = AF_INET6,
		.port   = ctx->user_port,
	};
	__builtin_memcpy(dst.ip, ctx->user_ip6, sizeof(dst.ip));

	struct udp_orig_key k = {
		.src_port = ctx->sk->src_port,
		.family   = AF_INET6,
	};
	bpf_map_update_elem(&udp_orig_dst, &k, &dst, BPF_ANY);

	if (cfg_verbose())
		bpf_printk("[vproxy] sendmsg6 sport=%d", k.src_port);

	/* Redirect to ::1:proxy_port */
	ctx->user_ip6[0] = 0;
	ctx->user_ip6[1] = 0;
	ctx->user_ip6[2] = 0;
	ctx->user_ip6[3] = bpf_htonl(1);
	ctx->user_port   = bpf_htons((__u16)proxy_port);
	return 1;
}
