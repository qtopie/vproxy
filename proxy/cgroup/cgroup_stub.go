//go:build !linux
// +build !linux

package cgroup

func EnsureVProxyCgroup() error {
	return nil
}

func MoveProcessToVProxyCgroup(pid int) error {
	return nil
}

func IsProcessInVProxyCgroup() bool {
	return false
}
