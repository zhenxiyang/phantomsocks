package phantomtcp

import (
	"net"
	"syscall"
	"time"
)

func DialConnInfo(laddr, raddr *net.TCPAddr, conf *Config, payload []byte) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	var err error
	if (conf.Option & (OPT_MSS | OPT_TFO | OPT_HTFO | OPT_KEEPALIVE)) != 0 {
		if (conf.Option & OPT_SSEG) == 0 {
			AddConn(raddr.String())
		}
		d := net.Dialer{LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				err := c.Control(func(fd uintptr) {
					if (conf.Option & OPT_MSS) != 0 {
						syscall.SetsockoptInt(int(fd),
							syscall.SOL_TCP, syscall.TCP_MAXSEG, int(conf.MSS))
					}
					if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
						syscall.SetsockoptInt(int(fd), 6, 30, 1)
					}
					if (conf.Option & OPT_KEEPALIVE) != 0 {
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
					}
				})
				return err
			}}
		conn, err = d.Dial("tcp", raddr.String())
		if err == nil && payload != nil {
			_, err = conn.Write(payload)
		}
		if (conf.Option & OPT_SSEG) != 0 {
			return conn, nil, err
		}
	} else {
		AddConn(raddr.String())
		conn, err = net.DialTCP("tcp", laddr, raddr)
	}

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

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())

	if LocalTCPAddr.IP.To4() == nil {
		mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(file.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		raw := mtuinfo.Addr
		var ip net.IP = raw.Addr[:]

		port := int(raw.Port&0xFF)<<8 | int(raw.Port&0xFF00)>>8
		TCPAddr := net.TCPAddr{ip, port, ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	} else {
		raw, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		var ip net.IP = raw.Multiaddr[4:8]
		port := int(raw.Multiaddr[2])<<8 | int(raw.Multiaddr[3])
		TCPAddr := net.TCPAddr{ip, port, ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	}

	return nil, nil
}
