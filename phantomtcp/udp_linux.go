package phantomtcp

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strconv"

	"github.com/macronut/go-tproxy"
)

func TProxyUDP(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	client, err := tproxy.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	data := make([]byte, 1500)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(client, data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		dstIP4 := dstAddr.IP.To4()
		if dstIP4 != nil {
			if dstIP4[0] == VirtualAddrPrefix {
				index := int(binary.BigEndian.Uint16(dstIP4[2:4]))
				if index >= len(Nose) {
					continue
				}
				host = Nose[index]
			} else {
				continue
			}
		} else if dstAddr.IP[0] == 0 {
			index := int(binary.BigEndian.Uint32(dstAddr.IP[12:16]))
			if index >= len(Nose) {
				continue
			}
			host = Nose[index]
		} else {
			continue
		}

		server := ConfigLookup(host)
		if server.Hint&(OPT_UDP|OPT_HTTP3) == 0 {
			continue
		}
		if server.Hint&(OPT_HTTP3) != 0 {
			if GetQUICVersion(data[:n]) == 0 {
				continue
			}
		}

		logPrintln(1, "TProxy(UDP):", srcAddr, "->", host, dstAddr.Port, server)

		localConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var remoteConn net.Conn = nil
		var proxyConn net.Conn = nil
		if server.Protocol != 0 {
			remoteAddress := net.JoinHostPort(host, strconv.Itoa(dstAddr.Port))
			remoteConn, proxyConn, err = server.DialProxyUDP(remoteAddress)
		} else {
			_, ips := NSLookup(host, server.Hint, server.DNS)
			if ips == nil {
				localConn.Close()
				continue
			}

			raddr := net.UDPAddr{IP: ips[0], Port: dstAddr.Port}
			remoteConn, err = net.DialUDP("udp", nil, &raddr)
		}

		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
			continue
		}

		if server.Hint&OPT_ZERO != 0 {
			zero_data := make([]byte, 8+rand.Intn(1024))
			_, err = remoteConn.Write(zero_data)
			if err != nil {
				logPrintln(1, err)
				localConn.Close()
				if proxyConn != nil {
					proxyConn.Close()
				}
				continue
			}
		}

		_, err = remoteConn.Write(data[:n])
		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
			continue
		}

		go func(localConn, remoteConn, proxyConn net.Conn) {
			relayUDP(localConn, remoteConn)
			remoteConn.Close()
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
		}(localConn, remoteConn, proxyConn)
	}
}
