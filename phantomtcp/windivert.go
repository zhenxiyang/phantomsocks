// +build windows
// +build !windows

package phantomtcp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/macronut/godivert"
)

var winDivert *godivert.WinDivertHandle

func DevicePrint() {
}

func connectionMonitor(synack bool, layer uint8) {
	var filter string
	if synack {
		filter = "inbound and tcp.Syn"
	} else {
		filter = "outbound and tcp.Syn"
	}

	var err error
	winDivert, err = godivert.WinDivertOpen(filter, layer, 1, 0)
	if err != nil {
		fmt.Printf("winDivert open failed: %v", err)
		return
	}
	defer winDivert.Close()

	for {
		divertpacket, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		winDivert.Send(divertpacket)

		ipv6 := divertpacket.Raw[0]>>4 == 6
		var packet gopacket.Packet
		if ipv6 {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv6, gopacket.Default)
		} else {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv4, gopacket.Default)
		}

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
					tcp.Seq = tcp.Ack
					tcp.Ack = ack
				} else {
					if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
					tcp.Seq++
				}

				ch := ConnInfo4[srcPort]
				connInfo := ConnectionInfo{nil, ip, *tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)
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
					tcp.Seq = tcp.Ack
					tcp.Ack = ack
				} else {
					if info.Option&OPT_SYNX2 != 0 {
						SendPacket(packet)
					}
					tcp.Seq++
				}

				ch := ConnInfo6[srcPort]
				connInfo := ConnectionInfo{nil, ip, *tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)
			}
		}
	}
}

func ConnectionMonitor(devices []string, synack bool) bool {
	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo, 1)
		ConnInfo6[i] = make(chan *ConnectionInfo, 1)
	}

	go connectionMonitor(synack, 0)
	return true
}

func SendPacket(packet gopacket.Packet) error {
	payload := packet.LinkLayer().LayerPayload()

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = payload
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()

	_, err := winDivert.Send(&divertpacket)
	return err
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
		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{19, 18, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		)
	} else if method&OPT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 10, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
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

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if method&OPT_TTL != 0 {
			ip.TTL = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	case *layers.IPv6:
		if method&OPT_TTL != 0 {
			ip.HopLimit = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	}

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = buffer.Bytes()
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()

	for i := 0; i < count; i++ {
		_, err := winDivert.Send(&divertpacket)
		if err != nil {
			return err
		}
	}

	return nil
}
