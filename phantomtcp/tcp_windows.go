package phantomtcp

import (
	"net"
	"time"
)

func DialConnInfo(laddr, raddr *net.TCPAddr, conf *Config, payload []byte) (net.Conn, *ConnectionInfo, error) {
	addr := raddr.String()

	AddConn(addr, conf.Option)
	timeout := time.Millisecond * 1500
	d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		DelConn(raddr.String())
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	ip4 := raddr.IP.To4()
	if ip4 != nil {
		select {
		case connInfo := <-ConnInfo4[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo := <-ConnInfo6[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	}

	DelConn(raddr.String())
	return conn, nil, nil
}

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	LocalAddr := conn.LocalAddr()
	LocalTCPAddr := LocalAddr.(*net.TCPAddr)

	if ip4 := LocalTCPAddr.IP.To4(); ip4 != nil {
		if ip4[0] == 127 && ip4[1] == 255 {
			ip4[0] = 6
			ip4[1] = 0
			LocalTCPAddr.IP = ip4
			RemoteTCPAddr := conn.RemoteAddr().(*net.TCPAddr).IP.To4()
			LocalTCPAddr.Port = int(RemoteTCPAddr[2])<<8 | int(RemoteTCPAddr[3])
		}
	}

	return LocalTCPAddr, nil
}
