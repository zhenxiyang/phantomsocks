//+build !darwin
//+build !linux

package proxy

import (
	"net"
)

func SetProxy(dev, address string, state bool) error {
	return nil
}

func SetKeepAlive(conn net.Conn) error {
	return nil
}
