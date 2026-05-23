//go:build !linux && !android
// +build !linux,!android

package ebpf

func SetupTC(dev string, proxyMark int, verbose bool) error {
	return nil
}

func AddMacToWhitelist(macStr string) error {
	return nil
}

func RemoveMacFromWhitelist(macStr string) error {
	return nil
}

func AddIPToWhitelist(ipStr string) error {
	return nil
}

func RemoveIPFromWhitelist(ipStr string) error {
	return nil
}

func isLittleEndian() bool {
	return false
}

func CloseTC() {
}
