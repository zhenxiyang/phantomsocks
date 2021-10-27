// +build linux
// +build rawsocket

package phantomtcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DevicePrint() {
}

func connectionMonitor(device string, ipv6 bool) {
	fmt.Printf("Device: %v\n", device)

	var err error
	localaddr, err := GetLocalAddr(device, ipv6)
	if err != nil {
		logPrintln(1, err)
		return
	}

	var handle *net.IPConn
	if ipv6 {
		if localaddr == nil {
			logPrintln(1, "no IPv6 on", device)
			return
		}
		netaddr, _ := net.ResolveIPAddr("ip6", localaddr.IP.String())
		handle, err = net.ListenIP("ip6:tcp", netaddr)
	} else {
		if localaddr == nil {
			logPrintln(1, "no IPv4 on", device)
			return
		}
		netaddr, _ := net.ResolveIPAddr("ip4", localaddr.IP.String())
		handle, err = net.ListenIP("ip4:tcp", netaddr)
	}

	if err != nil {
		fmt.Printf("sockraw open failed: %v", err)
		return
	}
	defer handle.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := handle.ReadFrom(buf)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var tcp layers.TCP

		tcp.DecodeFromBytes(buf[:n], nil)

		if tcp.SYN != true {
			continue
		}
		srcPort := tcp.DstPort
		synAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(tcp.SrcPort)))
		_, ok := ConnSyn.Load(synAddr)
		if ok {
			if ipv6 {
				var ip layers.IPv6
				ip.Version = 6
				ip.TrafficClass = 5
				ip.FlowLabel = 0
				ip.Length = 0
				ip.NextHeader = 6
				ip.HopLimit = 64
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.HopByHop = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo6[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
			} else {
				var ip layers.IPv4
				ip.Version = 4
				ip.IHL = 5
				ip.TOS = 0
				ip.Length = 0
				ip.Id = 0
				ip.Flags = 0
				ip.FragOffset = 0
				ip.TTL = 64
				ip.Protocol = 6
				ip.Checksum = 0
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.Options = nil
				ip.Padding = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo4[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
			}
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	if devices == nil {
		DevicePrint()
		return false
	}

	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo)
		ConnInfo6[i] = make(chan *ConnectionInfo)
	}

	for i := 0; i < len(devices); i++ {
		go connectionMonitor(devices[i], true)
		go connectionMonitor(devices[i], false)
	}

	return true
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, method uint32, ttl uint8, count int) error {
	ipLayer := connInfo.IP

	tcpLayer := &layers.TCP{
		SrcPort:    connInfo.TCP.SrcPort,
		DstPort:    connInfo.TCP.DstPort,
		Seq:        connInfo.TCP.Seq,
		Ack:        connInfo.TCP.Ack,
		DataOffset: 5,
		ACK:        true,
		PSH:        true,
		Window:     connInfo.TCP.Window,
	}

	if method&OPT_WMD5 != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{19, 16, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	} else if method&OPT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}
	}

	if method&OPT_NACK != 0 {
		tcpLayer.ACK = false
		tcpLayer.Ack = 0
	} else if method&OPT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true

	if method&OPT_WCSUM == 0 {
		options.ComputeChecksums = true
	}

	if method&OPT_WSEQ != 0 {
		tcpLayer.Seq--
		fakepayload := make([]byte, len(payload)+1)
		fakepayload[0] = 0xFF
		copy(fakepayload[1:], payload)
		payload = fakepayload
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	var sa syscall.Sockaddr
	var domain int

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if method&OPT_TTL != 0 {
			ip.TTL = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
		var addr [4]byte
		copy(addr[:4], ip.DstIP.To4()[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: 0}
		domain = syscall.AF_INET
	case *layers.IPv6:
		if method&OPT_TTL != 0 {
			ip.HopLimit = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
		var addr [16]byte
		copy(addr[:16], ip.DstIP[:16])
		sa = &syscall.SockaddrInet6{Addr: addr, Port: 0}
		domain = syscall.AF_INET6
	}

	raw_fd, err := syscall.Socket(domain, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(raw_fd)
		return err
	}
	outgoingPacket := buffer.Bytes()

	for i := 0; i < count; i++ {
		err = syscall.Sendto(raw_fd, outgoingPacket, 0, sa)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
	}
	syscall.Close(raw_fd)

	return nil
}

func SendJumboUDPPacket(laddr, raddr *net.UDPAddr, payload []byte) error {
	var sa syscall.Sockaddr
	var lsa syscall.Sockaddr
	var domain int

	var outgoingPacket [9000]byte
	packetsize := len(payload)
	ip4 := raddr.IP.To4()
	if ip4 != nil {
		copy(outgoingPacket[:], []byte{69, 0, 0, 0, 141, 152, 64, 0, 64, 17, 0, 0})
		packetsize += 8
		//binary.BigEndian.PutUint16(outgoingPacket[24:], uint16(packetsize))
		binary.BigEndian.PutUint16(outgoingPacket[24:], uint16(0))
		packetsize += 20
		binary.BigEndian.PutUint16(outgoingPacket[2:], uint16(packetsize))
		copy(outgoingPacket[12:], laddr.IP.To4())
		copy(outgoingPacket[16:], ip4)
		binary.BigEndian.PutUint16(outgoingPacket[20:], uint16(laddr.Port))
		binary.BigEndian.PutUint16(outgoingPacket[22:], uint16(raddr.Port))
		copy(outgoingPacket[28:], payload)

		binary.BigEndian.PutUint16(outgoingPacket[26:], ComputeUDPChecksum(outgoingPacket[:packetsize]))

		var ip [4]byte
		copy(ip[:], ip4)
		sa = &syscall.SockaddrInet4{Addr: ip, Port: 0}
		copy(ip[:], laddr.IP.To4())
		lsa = &syscall.SockaddrInet4{Addr: ip, Port: 0}
		domain = syscall.AF_INET
	} else {
		var ip [16]byte
		copy(ip[:], raddr.IP.To16())
		sa = &syscall.SockaddrInet6{Addr: ip, Port: 0}
		copy(ip[:], laddr.IP.To16())
		lsa = &syscall.SockaddrInet6{Addr: ip, Port: 0}
		domain = syscall.AF_INET6
	}

	raw_fd, err := syscall.Socket(domain, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(raw_fd)
		return err
	}
	err = syscall.Bind(raw_fd, lsa)
	if err != nil {
		syscall.Close(raw_fd)
		return err
	}

	err = syscall.Sendto(raw_fd, outgoingPacket[:packetsize], 0, sa)
	syscall.Close(raw_fd)
	if err != nil {
		return err
	}

	return nil
}

func UDPMonitor(devices []string) bool {
	return true
}
