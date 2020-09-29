// +build !linux !mipsle
//// +build !windows

package phantomtcp

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var pcapHandle *pcap.Handle

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
			result, ok := ConnSyn.Load(synAddr)
			if ok {
				info := result.(SynInfo)

				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.TTL = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo4[srcPort]
				var connInfo *ConnectionInfo
				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					connInfo = &ConnectionInfo{link, ip, *tcp}
				default:
					connInfo = &ConnectionInfo{nil, ip, *tcp}
				}

				if !synack {
					if info.Option&(OPT_TFO|OPT_HTFO) != 0 {
						if ip.TOS == 252 {
							payload := tcp.Payload
							ip.TTL = 64
							ip.TOS = 0
							if len(tcp.Payload) < 2 {
								ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, 1)
								connInfo = nil
							} else {
								payload[0] = 0x16
								payload[1] = 0x03
								ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, 1)
							}
						}
					} else if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			}
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
			result, ok := ConnSyn.Load(synAddr)
			if ok {
				info := result.(SynInfo)
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.HopLimit = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo6[srcPort]
				var connInfo *ConnectionInfo
				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					connInfo = &ConnectionInfo{link, ip, *tcp}
				default:
					connInfo = &ConnectionInfo{nil, ip, *tcp}
				}

				if !synack {
					if info.Option&(OPT_TFO|OPT_HTFO) != 0 {
						if ip.TrafficClass == 63 {
							payload := tcp.Payload
							ip.HopLimit = 64
							ip.TrafficClass = 0
							if len(payload) < 2 {
								connInfo = nil
								ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, 1)
							} else {
								payload[0] = 0x16
								payload[1] = 0x03
								ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, 1)
							}
						}
					} else if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			}
		}
	}
}

func ConnectionMonitor(devices []string, synack bool) bool {
	if devices == nil {
		DevicePrint()
		return false
	}

	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo)
		ConnInfo6[i] = make(chan *ConnectionInfo)
	}

	for i := 0; i < len(devices); i++ {
		go connectionMonitor(devices[i], synack)
	}

	return true
}
