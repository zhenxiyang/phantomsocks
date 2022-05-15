//go:build !pcap && !rawsocket && !windivert
// +build !pcap,!rawsocket,!windivert

package phantomtcp

func DevicePrint() {
}

func ConnectionMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	return nil
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}
