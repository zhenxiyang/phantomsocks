// +build !linux !mipsle
// +build !windows

package phantomtcp

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func DevicePrint() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

var SynLock sync.RWMutex
var ConnSyn map[string]int
var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo

var pcapHandle *pcap.Handle

func connectionMonitor(device string, synack bool) {
	fmt.Printf("Device: %v\n", device)

	snapLen := int32(65535)

	var filter string
	if synack {
		filter = "(ip6[6]==6 and ip6[53]&18==18) or (tcp[13]&18==18)"
	} else {
		filter = "(ip6[6]==6 and ip6[53]&18==2) or (tcp[13]&18==2)"
	}

	var err error
	pcapHandle, err = pcap.OpenLive(device, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		return
	}

	if err = pcapHandle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = false
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		link := packet.LinkLayer()
		ip := packet.NetworkLayer()
		tcp := packet.TransportLayer().(*layers.TCP)

		switch ip := ip.(type) {
		case *layers.IPv4:
			var srcPort layers.TCPPort
			var synAddr string
			if synack {
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
			}
			SynLock.RLock()
			_, ok := ConnSyn[synAddr]
			if ok {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.TTL = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack
					tcp.Ack = ack
				} else {
					tcp.Seq++
				}

				ch := ConnInfo4[srcPort]
				select {
				case <-ch:
				default:
				}

				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					ch <- &ConnectionInfo{link, ip, *tcp}
				default:
					ch <- &ConnectionInfo{nil, ip, *tcp}
				}
			}
			SynLock.RUnlock()
		case *layers.IPv6:
			var srcPort layers.TCPPort
			var synAddr string
			if synack {
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
			}
			SynLock.RLock()
			_, ok := ConnSyn[synAddr]
			if ok {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.HopLimit = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack
					tcp.Ack = ack
				} else {
					tcp.Seq++
				}

				ch := ConnInfo6[srcPort]
				select {
				case <-ch:
				default:
				}

				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					ch <- &ConnectionInfo{link, ip, *tcp}
				default:
					ch <- &ConnectionInfo{nil, ip, *tcp}
				}
			}
			SynLock.RUnlock()
		}
	}
}

func ConnectionMonitor(devices []string, synack bool) bool {
	if devices == nil {
		DevicePrint()
		return false
	}

	ConnSyn = make(map[string]int, 65536)
	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo, 1)
		ConnInfo6[i] = make(chan *ConnectionInfo, 1)
	}

	for i := 0; i < len(devices); i++ {
		go connectionMonitor(devices[i], synack)
	}

	return true
}

func SendFakePacket(connInfo *ConnectionInfo, payload []byte, config *Config, count int) error {
	linkLayer := connInfo.Link
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

	if config.Option&OPT_WMD5 != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{19, 18, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	} else if config.Option&OPT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 10, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}
	}

	if config.Option&OPT_NACK != 0 {
		tcpLayer.ACK = false
		tcpLayer.Ack = 0
	} else if config.Option&OPT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true

	if config.Option&OPT_WCSUM == 0 {
		options.ComputeChecksums = true
	}

	if config.Option&OPT_WSEQ != 0 {
		tcpLayer.Seq -= 1
		fakepayload := make([]byte, len(payload)+1)
		fakepayload[0] = 0xFF
		copy(fakepayload[1:], payload)
		payload = fakepayload
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	if linkLayer != nil {
		link := linkLayer.(*layers.Ethernet)
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if config.Option&OPT_TTL != 0 {
				ip.TTL = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		case *layers.IPv6:
			if config.Option&OPT_TTL != 0 {
				ip.HopLimit = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err := pcapHandle.WritePacketData(outgoingPacket)
			if err != nil {
				return err
			}
		}
	} else {
		var sa syscall.Sockaddr
		var lsa syscall.Sockaddr
		var domain int

		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if config.Option&OPT_TTL != 0 {
				ip.TTL = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [4]byte
			copy(addr[:4], ip.DstIP.To4()[:4])
			sa = &syscall.SockaddrInet4{Addr: addr, Port: 0}
			var laddr [4]byte
			copy(laddr[:4], ip.SrcIP.To4()[:4])
			lsa = &syscall.SockaddrInet4{Addr: laddr, Port: 0}
			domain = syscall.AF_INET
		case *layers.IPv6:
			if config.Option&OPT_TTL != 0 {
				ip.HopLimit = config.TTL
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [16]byte
			copy(addr[:16], ip.DstIP[:16])
			sa = &syscall.SockaddrInet6{Addr: addr, Port: 0}
			var laddr [16]byte
			copy(laddr[:16], ip.SrcIP[:16])
			lsa = &syscall.SockaddrInet6{Addr: laddr, Port: 0}
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
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err = syscall.Sendto(raw_fd, outgoingPacket, 0, sa)
			if err != nil {
				syscall.Close(raw_fd)
				return err
			}
		}
		syscall.Close(raw_fd)
	}

	return nil
}
