//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// 定义一个 Map 用来存储需要代理的 Source MAC 地址
// Key: MAC地址 (6字节，但bpf map key通常对齐到4/8字节，这里用u64存方便)
// Value: 任意 (u8)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);   // MAC地址作为 Key
    __type(value, __u8);
} mac_whitelist SEC(".maps");

// IP 白名单
// Key: IPv4地址 (u32, Network Byte Order)
// Value: 任意 (u8)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} ip_whitelist SEC(".maps");

// 代理标记，Go 代码可以重写这个常量
volatile const __u32 proxy_mark = 0x1;
// TProxy listen port (host order). Can be overridden from user-space when
// embedding this BPF object. Default is 12345.
volatile const __u16 tproxy_port = 12345;
// Verbose logging. Can be overridden from user-space.
volatile const __u8 verbose_mode = 0;

// 辅助函数：将6字节MAC转为u64 Key
static __always_inline __u64 mac_to_u64(__u8 *mac) {
    __u64 key = 0;
    /*
     * Pack MAC bytes into a u64 in big-endian order so that
     * mac[0] is the most-significant byte. This makes user-space
     * insertion of keys (when using the same packing) deterministic
     * and avoids ambiguity from memcpy and host endianness.
     */
    key = ((__u64)mac[0] << 40) |
          ((__u64)mac[1] << 32) |
          ((__u64)mac[2] << 24) |
          ((__u64)mac[3] << 16) |
          ((__u64)mac[4] << 8)  |
          ((__u64)mac[5] << 0);
    return key;
}

SEC("classifier")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. 解析 Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // 2. 检查协议，我们只代理 IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // 3. MAC/IP 地址过滤
    // Source MAC 是 eth->h_source
    __u64 mac_key = mac_to_u64(eth->h_source);
    __u8 *exists_mac = bpf_map_lookup_elem(&mac_whitelist, &mac_key);

    __u8 *exists_ip = NULL;
    struct iphdr *iph = (void *)(eth + 1);
    __u32 saddr = 0;

    // 只有当是 IPv4 包，并且 eth 后面还有足够数据时才查 IP
    if ((void *)(iph + 1) <= data_end) {
        saddr = iph->saddr; // saddr 已经是 Network Byte Order
        exists_ip = bpf_map_lookup_elem(&ip_whitelist, &saddr);
    }

    // Explicit NULL checks to satisfy verifier and calculate whitelist status
    int is_whitelisted = 0;
    if (exists_mac) is_whitelisted = 1;
    if (exists_ip) is_whitelisted = 1;

    if (verbose_mode) {
        bpf_printk("[vproxy] tc: MAC=%llx IP=%x Listed=%d", mac_key, saddr, is_whitelisted);
    }
    
    if (!is_whitelisted) {
        return TC_ACT_OK;
    }

    // 4. 解析 IP Header (已解析，做后续检查)
    // struct iphdr *iph = (void *)(eth + 1); // moved up
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_OK;
    }

    // 5. 排除组播和广播 (简单检查)
    if (iph->daddr == 0xFFFFFFFF) { // 255.255.255.255
         return TC_ACT_OK;
    }

    // 6. 打标记 (Marking)
    /*
     * 混合模式核心:
     * eBPF 只负责 ACL 和高性能打标 (Marking)。
     * 具体的流量导向 (Steering) 交给 Linux Kernel 的 Policy Routing (ip rule + ip route).
     * 这样可以避开 bpf_sk_assign 的兼容性陷阱。
     */
    skb->mark = proxy_mark;

    if (verbose_mode) {
        bpf_printk("[vproxy] marked packet (mark=%x), passing to stack", proxy_mark);
    }

    // 返回 TC_ACT_OK 表示“数据包有效，继续传递给内核网络栈”
    // 内核会根据 skb->mark 查路由表 (Table 100)，路由表会说 “local socket”，
    // 然后 TProxy Listener 捕获它。
    return TC_ACT_OK;
}
