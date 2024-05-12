package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/lysShub/netkit/packet"
	"github.com/stretchr/testify/require"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type TCP struct {
	c cipher.AEAD

	pseudoSum1 uint16
}

var _ Crypto = (*TCP)(nil)

const (
	nonces    = 12
	noncesOff = 4
)

// NewTCP a tcp AES-GCM-128 crypter, not update tcp Seq/Ack
func NewTCP(key [Bytes]byte, pseudoSum1 uint16) (*TCP, error) {
	var g = &TCP{pseudoSum1: pseudoSum1}

	if block, err := aes.NewCipher(key[:]); err != nil {
		return nil, err
	} else {
		if g.c, err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
	}
	if debug.Debug() {
		require.Equal(test.T(), Bytes, g.c.Overhead())
	}
	return g, nil
}

func (g *TCP) Overhead() int { return g.c.Overhead() }

func (g *TCP) Encrypt(tcp *packet.Packet) {
	hdr := header.TCP(tcp.AppendN(Bytes).ReduceN(Bytes).Bytes())

	i := hdr.DataOffset()
	g.c.Seal(hdr[i:i], nonce(hdr), hdr[i:], nil)
	hdr = hdr[:len(hdr)+Bytes]

	hdr.SetChecksum(0)
	psosum := checksum.Combine(g.pseudoSum1, uint16(len(hdr)))
	hdr.SetChecksum(^checksum.Checksum(hdr, psosum))

	tcp.SetData(len(hdr))
	if debug.Debug() {
		test.ValidTCP(test.T(), tcp.Bytes(), g.pseudoSum1)
	}
}

func (g *TCP) Decrypt(tcp *packet.Packet) error {
	if debug.Debug() {
		test.ValidTCP(test.T(), tcp.Bytes(), g.pseudoSum1)
	}
	hdr := header.TCP(tcp.Bytes())

	i := hdr.DataOffset()
	_, err := g.c.Open(hdr[i:i], nonce(hdr), hdr[i:], nil)
	if err != nil {
		return err
	}
	hdr = hdr[:len(hdr)-Bytes]

	hdr.SetChecksum(0)
	psosum := checksum.Combine(g.pseudoSum1, uint16(len(hdr)))
	hdr.SetChecksum(^checksum.Checksum(hdr, psosum))

	tcp.SetData(len(hdr))
	if debug.Debug() {
		test.ValidTCP(test.T(), tcp.Bytes(), g.pseudoSum1)
	}
	return nil
}

func nonce(tcp []byte) []byte {
	return tcp[noncesOff : noncesOff+nonces]
}
