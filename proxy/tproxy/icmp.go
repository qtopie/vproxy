package tproxy

import (
	"encoding/binary"
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"golang.zx2c4.com/wireguard/tun"
)

func handleICMPv4(buf []byte) []byte {
	if len(buf) < header.IPv4MinimumSize {
		return nil
	}
	ipHdr := header.IPv4(buf)
	if ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber {
		return nil
	}
	icmpBuf := ipHdr.Payload()
	if len(icmpBuf) < header.ICMPv4MinimumSize {
		return nil
	}
	icmpHdr := header.ICMPv4(icmpBuf)
	if icmpHdr.Type() != header.ICMPv4Echo {
		return nil
	}

	// Create reply
	replyBuf := make([]byte, len(buf))
	copy(replyBuf, buf)
	replyIPHdr := header.IPv4(replyBuf)
	replyICMPHdr := header.ICMPv4(replyIPHdr.Payload())

	// Swap addresses
	src := replyIPHdr.SourceAddress()
	dst := replyIPHdr.DestinationAddress()
	replyIPHdr.SetSourceAddress(dst)
	replyIPHdr.SetDestinationAddress(src)

	// Set type to echo reply
	replyICMPHdr.SetType(header.ICMPv4EchoReply)

	// Checksum ICMP
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(checksum.Checksum(replyICMPHdr, 0))

	// Checksum IP
	replyIPHdr.SetChecksum(0)
	replyIPHdr.SetChecksum(replyIPHdr.CalculateChecksum())

	return replyBuf
}

func handleICMPv6(buf []byte) []byte {
	if len(buf) < header.IPv6MinimumSize {
		return nil
	}
	ipHdr := header.IPv6(buf)
	if ipHdr.NextHeader() != uint8(header.ICMPv6ProtocolNumber) {
		return nil
	}
	icmpBuf := ipHdr.Payload()
	if len(icmpBuf) < header.ICMPv6MinimumSize {
		return nil
	}
	icmpHdr := header.ICMPv6(icmpBuf)
	if icmpHdr.Type() != header.ICMPv6EchoRequest {
		return nil
	}

	// Create reply
	replyBuf := make([]byte, len(buf))
	copy(replyBuf, buf)
	replyIPHdr := header.IPv6(replyBuf)
	replyICMPHdr := header.ICMPv6(replyIPHdr.Payload())

	// Swap addresses
	src := replyIPHdr.SourceAddress()
	dst := replyIPHdr.DestinationAddress()
	replyIPHdr.SetSourceAddress(dst)
	replyIPHdr.SetDestinationAddress(src)

	// Set type to echo reply
	replyICMPHdr.SetType(header.ICMPv6EchoReply)

	// Checksum ICMPv6 (requires pseudo-header)
	replyICMPHdr.SetChecksum(0)
	payload := replyICMPHdr[header.ICMPv6MinimumSize:]
	cksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      replyICMPHdr[:header.ICMPv6MinimumSize],
		Src:         replyIPHdr.SourceAddress(),
		Dst:         replyIPHdr.DestinationAddress(),
		PayloadCsum: ^checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	})
	replyICMPHdr.SetChecksum(cksum)

	return replyBuf
}

// ProcessICMP handles ICMP echo requests locally and returns a reply if applicable.
// It returns (reply, version, handled).
func ProcessICMP(pktBuf []byte) ([]byte, int, bool) {
	if len(pktBuf) < 1 {
		return nil, 0, false
	}
	version := int(pktBuf[0] >> 4)
	var reply []byte
	if version == 4 {
		reply = handleICMPv4(pktBuf)
	} else if version == 6 {
		reply = handleICMPv6(pktBuf)
	}
	if reply != nil {
		return reply, version, true
	}
	return nil, version, false
}

// CheckAndWriteICMP checks if a packet is an ICMP echo request and writes a reply to the TUN device.
// It returns true if the packet was handled.
func CheckAndWriteICMP(dev tun.Device, pktBuf []byte, offset int) bool {
	reply, version, handled := ProcessICMP(pktBuf)
	if !handled {
		return false
	}

	// Write reply back to TUN
	outPacket := make([]byte, len(reply)+offset)
	copy(outPacket[offset:], reply)
	
	if offset > 0 {
		// Set AF_INET/AF_INET6 for platforms that use a PI header (e.g. Darwin utun)
		if version == 6 {
			binary.BigEndian.PutUint32(outPacket[:4], syscall.AF_INET6)
		} else {
			binary.BigEndian.PutUint32(outPacket[:4], syscall.AF_INET)
		}
	}
	
	dev.Write([][]byte{outPacket}, offset)
	return true
}
