package capture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodePacket decodes raw ethernet frame into DecodedPacket using gopacket.
// Uses NoCopy mode to minimize allocations.
func decodePacket(raw []byte, timestamp time.Time) *DecodedPacket {
	if len(raw) == 0 {
		return nil
	}

	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.NoCopy)

	// Check for decode errors
	if errLayer := pkt.ErrorLayer(); errLayer != nil {
		return nil
	}

	// Decode Ethernet layer
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok || eth == nil {
		return nil
	}

	result := &DecodedPacket{
		Raw:       raw,
		Timestamp: timestamp,
		SrcMAC:    eth.SrcMAC.String(),
		DstMAC:    eth.DstMAC.String(),
		Length:    len(raw),
		Meta:      &PacketMeta{},
	}

	// Decode IPv4 layer
	ipv4Layer := pkt.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok || ipv4 == nil {
		return nil
	}

	result.SrcIP = ipv4.SrcIP.String()
	result.DstIP = ipv4.DstIP.String()
	result.Protocol = uint8(ipv4.Protocol)

	// Decode TCP layer
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok && tcp != nil {
			result.SrcPort = uint16(tcp.SrcPort)
			result.DstPort = uint16(tcp.DstPort)
			result.TCPFlags = buildTCPFlags(tcp)
			result.TCPSeq = tcp.Seq
		}
	}

	// Decode UDP layer
	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok && udp != nil {
			result.SrcPort = uint16(udp.SrcPort)
			result.DstPort = uint16(udp.DstPort)
		}
	}

	return result
}

// buildTCPFlags constructs the TCP flags byte from individual boolean fields.
// Encoding: FIN=bit0, SYN=bit1, RST=bit2, ACK=bit4.
func buildTCPFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= 1 << 0
	}
	if tcp.SYN {
		flags |= 1 << 1
	}
	if tcp.RST {
		flags |= 1 << 2
	}
	if tcp.ACK {
		flags |= 1 << 4
	}
	return flags
}
