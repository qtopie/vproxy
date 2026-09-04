module github.com/qtopie/vproxy

go 1.25.5

require (
	github.com/cilium/ebpf v0.20.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/net v0.52.0
	golang.org/x/sys v0.43.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	google.golang.org/grpc v1.80.0
	gvisor.dev/gvisor v0.0.0-20260523100227-85b606a040c1
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace gvisor.dev/gvisor => github.com/google/gvisor v0.0.0-20260519190036-266ba6c868f3

replace golang.zx2c4.com/wintun => ./third_party/wintun
