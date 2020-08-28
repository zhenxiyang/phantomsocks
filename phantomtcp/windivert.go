package phantomtcp

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/macronut/godivert"
)

func DevicePrint() {
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

var winDivert *godivert.WinDivertHandle

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

				ch <- &ConnectionInfo{nil, ip, *tcp}
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

				ch <- &ConnectionInfo{nil, ip, *tcp}
			}
			SynLock.RUnlock()
		}
	}
}

func ConnectionMonitor(devices []string, synack bool) {
	connectionMonitor(synack, 0)
	connectionMonitor(synack, 1)
}

func SendFakePacket(connInfo *ConnectionInfo, payload []byte, config *Config, count int) error {
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

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if config.Option&OPT_TTL != 0 {
			ip.TTL = config.TTL
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	case *layers.IPv6:
		if config.Option&OPT_TTL != 0 {
			ip.HopLimit = config.TTL
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
