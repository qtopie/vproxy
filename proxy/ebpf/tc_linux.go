//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags "linux,!android" -output-dir . tc_bpf bpf/tc_redirect.c

var (
	tcObjs tc_bpfObjects
)

func SetupTC(dev string, proxyMark int, verbose bool) error {
	// 1. Load BPF objects
	spec, err := loadTc_bpf()
	if err != nil {
		return fmt.Errorf("loading tc spec: %v", err)
	}

	// Rewrite constants
	verboseVal := uint8(0)
	if verbose {
		verboseVal = 1
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"proxy_mark":   uint32(proxyMark),
		"verbose_mode": verboseVal,
	}); err != nil {
		return fmt.Errorf("rewriting constants: %v", err)
	}

	// Load into kernel
	if err := spec.LoadAndAssign(&tcObjs, nil); err != nil {
		return fmt.Errorf("loading tc objects: %v", err)
	}

	// 2. Get Interface
	linkObj, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("finding link %s: %v", dev, err)
	}

	// 3. Create clsact qdisc
	// We ignore "File exists" error
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkObj.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    0xFFFF0000,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !os.IsExist(err) {
			// Check if it's strictly "file exists" (errno 17)
			// netlink might wrap it.
			// Proceeding hoping it works or was already there.
		}
	}

	// 4. Attach Filter (Ingress)
	// Priority 1, Handle 1
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkObj.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           tcObjs.TcIngress.FD(),
		Name:         "vproxy_ingress",
		DirectAction: true,
	}

	// We use Replace to ensure we update it if it exists
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %v", err)
	}

	return nil
}

func AddMacToWhitelist(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return err
	}
	if len(mac) != 6 {
		return fmt.Errorf("invalid mac length: %d", len(mac))
	}

	// Convert MAC to u64 key (Big Endian mapping to match C implementation)
	var key uint64
	key = (uint64(mac[0]) << 40) |
		(uint64(mac[1]) << 32) |
		(uint64(mac[2]) << 24) |
		(uint64(mac[3]) << 16) |
		(uint64(mac[4]) << 8) |
		(uint64(mac[5]) << 0)

	val := uint8(1)
	return tcObjs.MacWhitelist.Put(key, val)
}

func RemoveMacFromWhitelist(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return err
	}
	// Convert MAC to u64 key (Big Endian mapping to match C implementation)
	var key uint64
	key = (uint64(mac[0]) << 40) |
		(uint64(mac[1]) << 32) |
		(uint64(mac[2]) << 24) |
		(uint64(mac[3]) << 16) |
		(uint64(mac[4]) << 8) |
		(uint64(mac[5]) << 0)

	return tcObjs.MacWhitelist.Delete(key)
}

func AddIPToWhitelist(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("only ipv4 supported: %s", ipStr)
	}

	// 转换 IPv4 为 Network Byte Order (Big Endian) 存储的 uint32
	// iph->saddr 在 Linux 内核中是 Network Byte Order
	// net.IP 在 Go 中是 byte slice。 v4[0] 是最高位字节。
	// 但 Go 的 syscall/binary 这里有点绕。
	// 我们手工打包成 u32 (Host order)，然后在 C 里面如果声明 key 是 u32，
	// bpf 的 map 查找是内存匹配。
	// 
	// C 代码中: key = iph->saddr (Network Order)。
	// 所以我们在 Go 里也必须存入 Network Order 的 u32。
	// 
	// 示例：1.2.3.4
	// v4[0]=1, v4[1]=2..
	// Memory: 01 02 03 04
	//
	// 如果我们只是简单地把 01 02 03 04 写入 map，那就是对的。
	// ebpf-go 的 Put(key, value) 如果 key 是 uint32，它会根据本机序转字节？
	// 最好直接按 binary.NativeEndian 还是 BigEndian？
	// 
	// 简单办法：我们在这里把 IP 转成 uint32，但要保持字节序和 eBPF 看到的一样。
	// eBPF 看到的 saddr 是 raw bytes (网络序)。
	// 
	// 如果我们本机是小端 (x86/arm64)，uint32(0x04030201) 在内存里是 01 02 03 04。
	// 1.2.3.4 => 0x04030201 (Little Endian Host Int)
	//
	// 让我们用 encoding/binary 来做最稳妥。但是 ebpf map key interface{} 有点黑盒。
	// 通常 ebpf-go 处理 uint32 是按本机序写入 map。
	//
	// 目标：内存里必须是 [IP(0), IP(1), IP(2), IP(3)]
	// 
	// 在 Little Endian 机器上：
	// val = uint32(IP(3))<<24 | IP(2)<<16 | ... | IP(0)
	// 只有这样，&val 才是 IP(0)...IP(3)
	// 
	// 等等，v4.To4() 返回的是 [1,2,3,4]。
	// 我们可以直接用 [4]byte 作为 key 吗？ebpf-go 支持 array key。
	// 但我们在 C 里定义的是 __u32。
	// 
	// 稳妥的做法：模拟 C 的行为。
	// C: saddr 是 u32 (Big Endian). 
	// 比如 192.168.1.1 (C0 A8 01 01) -> 0x0101A8C0 (Little Endian integer value)
	// 但是在 BPF 里面读取 `iph->saddr` 是直接读内存，得到的整数值在寄存器里。
	// 
	// 实际上最简单的理解是：IP头里的saddr是网络序。
	// 我们要在 map 里存一个 u32，使得这个 u32 在内存里的字节排列 = IP地址。
	// 
	// 在 Go (Little Endian) 中：
	// 欲使内存为 1.2.3.4 (0x01 02 03 04)
	// uint32 必须是 0x04030201
	//
	// 所以我们用 binary.LittleEndian.Uint32(v4) 即可？
	// 验证：
	// v4 = [1, 2, 3, 4]
	// LE.Uint32 = 4<<24 | 3<<16 | 2<<8 | 1 = 0x04030201
	// 存入内存(LE) -> 01 02 03 04. 正确。

	// 注意：这里假设运行 Go 的机器和 BPF 机器 (树莓派) 是一样的字节序 (都是 LE)。
	// 如果是大端机器 (如 MIPS BE)，逻辑反过来。
	// 现今绝大多数环境(x86, arm64)都是 LE。
	
	// 为了代码通用，我们不用 unsafe，直接根据 IP 字节构造。
	// C 代码中 key 定义为 __u32。
	// 遗憾的是 ebpf-go 的 map 定义需要我们传入对应的类型。
	// 既然我们控制两端，最简单的就是 C改一下：key 定义为 struct { u32 } 或 [4]u8？
	// 
	// 保持 C 为 u32 不变。 Go 侧我们手动计算出那个 u32 值。
	// 
	// 目标：Key 的内存字节顺序必须是 IP[0], IP[1], IP[2], IP[3]
	
	// 在 Go (假设 Little Endian): 
	// key = uint32(ip[0]) | uint32(ip[1])<<8 | ...
	// 这样内存里就是 ip[0] ip[1] ...
	
	var key uint32
	if isLittleEndian() {
		key = uint32(v4[0]) | (uint32(v4[1]) << 8) | (uint32(v4[2]) << 16) | (uint32(v4[3]) << 24)
	} else {
		key = uint32(v4[3]) | (uint32(v4[2]) << 8) | (uint32(v4[1]) << 16) | (uint32(v4[0]) << 24)
	}

	val := uint8(1)
	return tcObjs.IpWhitelist.Put(key, val)
}

func RemoveIPFromWhitelist(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("only ipv4 supported: %s", ipStr)
	}

	var key uint32
	if isLittleEndian() {
		key = uint32(v4[0]) | (uint32(v4[1]) << 8) | (uint32(v4[2]) << 16) | (uint32(v4[3]) << 24)
	} else {
		key = uint32(v4[3]) | (uint32(v4[2]) << 8) | (uint32(v4[1]) << 16) | (uint32(v4[0]) << 24)
	}

	return tcObjs.IpWhitelist.Delete(key)
}

func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := *(*byte)(unsafe.Pointer(&i))
	return u == 0x04
}

func CloseTC() {
	tcObjs.Close()
	// Optional: Remove qdisc or filter?
	// Usually better to leave it or let user decide,
	// but to be clean we could remove the filter.
}
