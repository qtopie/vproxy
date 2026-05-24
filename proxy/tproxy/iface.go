package tproxy

// TCPOrigDstMap is the interface satisfied by *ebpf.Map when used to look up
// the original TCP destination stored by the BPF cgroup/connect4 hook.
// Defined here (not in the linux-only file) so that callers can reference it
// on all platforms.
type TCPOrigDstMap interface {
	LookupAndDelete(key, value interface{}) error
}
