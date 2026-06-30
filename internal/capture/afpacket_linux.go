//go:build linux

package capture

import "golang.org/x/sys/unix"

// setPromisc enables promiscuous mode on the given AF_PACKET socket
// for the specified network interface.
func setPromisc(sock, ifIndex int) error {
	mreq := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	return unix.SetsockoptPacketMreq(sock, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
}

// setFanout configures AF_PACKET fanout with hash mode on the given socket.
// This distributes packets across sockets in the same fanout group for
// improved capture performance on multi-core systems.
func setFanout(sock int) error {
	// Fanout group ID 0 with hash mode
	fanout := (0 << 16) | unix.PACKET_FANOUT_HASH
	return unix.SetsockoptInt(sock, unix.SOL_PACKET, unix.PACKET_FANOUT, fanout)
}
