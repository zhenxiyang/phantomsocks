// +build !wireguard

package phantomtcp

import (
	"net"
)

func WireGuardServer(service ServiceConfig) {
}

func WireGuardClient(client InterfaceConfig) error {
	return nil
}

func WireGuardDialTCP(device string, address *net.TCPAddr) (net.Conn, error){
	return nil, nil
}

func WireGuardDialUDP(device string, address *net.UDPAddr) (net.Conn, error){
	return nil, nil
}