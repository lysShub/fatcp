package crypto

import "github.com/lysShub/netkit/packet"

const (
	Bytes = 16
)

type Key = [Bytes]byte

type Crypto interface {
	Decrypt(pkt *packet.Packet) error
	Encrypt(pkt *packet.Packet)
}
