// +build !linux
// +build !linux !mipsle
//// +build !windows

package phantomtcp

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendPacket(packet gopacket.Packet) error {
	err := pcapHandle.WritePacketData(packet.Data())
	return err
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, method uint32, ttl uint8, count int) error {
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

	if method&OPT_WMD5 != 0 {
		tcpLayer.Options = append(connInfo.TCP.Options,
			layers.TCPOption{19, 18, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		)
	} else if method&OPT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 10, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}
	} else if method&OPT_TFO != 0 {
		tcpLayer.SYN = true
		tcpLayer.ACK = false
		tcpLayer.PSH = false
		tcpLayer.DataOffset = connInfo.TCP.DataOffset
		tcpLayer.Options = connInfo.TCP.Options
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

	if linkLayer != nil {
		link := linkLayer.(*layers.Ethernet)
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if method&OPT_TTL != 0 {
				ip.TTL = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		case *layers.IPv6:
			if method&OPT_TTL != 0 {
				ip.HopLimit = ttl
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
		return errors.New("Invalid LinkLayer")
	}

	return nil
}
