// +build !linux !mipsle

package phantomtcp

import (
	"fmt"
	"log"
	"net"
	"sync"

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

type SynInfo struct {
	Number uint32
	Option uint32
}

var SynLock sync.RWMutex
var ConnSyn map[string]SynInfo
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
			info, ok := ConnSyn[synAddr]
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
					if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
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
			info, ok := ConnSyn[synAddr]
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
					if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
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

	ConnSyn = make(map[string]SynInfo, 128)
	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo, 1)
		ConnInfo6[i] = make(chan *ConnectionInfo, 1)
	}

	for i := 0; i < len(devices); i++ {
		go connectionMonitor(devices[i], synack)
	}

	return true
}
