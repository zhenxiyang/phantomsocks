// +build !pcap
// +build !rawsocket
// +build !windivert

package phantomtcp

func DevicePrint() {
}

func connectionMonitor(device string) {
}

func udpMonitor(device string) {
}

func ConnectionMonitor(devices []string) bool {
	return false
}

func UDPMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, method uint32, ttl uint8, count int) error {
	return nil
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}
