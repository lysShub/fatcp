package crypto

import "github.com/lysShub/netkit/packet"

const (
	Bytes    = 16
	Overhead = Bytes
)

type Key = [Bytes]byte

type Crypto interface {
	Overhead() int
	Decrypt(pkt *packet.Packet) error
	Encrypt(pkt *packet.Packet)
}
