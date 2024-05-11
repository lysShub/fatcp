package crypto_test

import (
	"context"
	"io"
	"testing"

	"github.com/pkg/errors"

	"github.com/lysShub/fatcp/crypto"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/rawsock"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
)

func UnicomStackAndRaw(t *testing.T, s ustack.Ustack, raw rawsock.RawConn, pseudoSum1 uint16) {
	c, err := crypto.NewTCP(crypto.Key{0: 1}, pseudoSum1)
	require.NoError(t, err)

	go func() {
		var pkt = packet.Make(0, s.MTU())

		for {
			s.Outbound(context.Background(), pkt.SetHead(0))
			if pkt.Data() == 0 {
				return
			}

			pkt.SetHead(64)
			test.ValidIP(t, pkt.Bytes())

			c.EncryptRaw(pkt)

			test.ValidIP(t, pkt.Bytes())

			err := raw.Write(context.Background(), pkt)
			require.NoError(t, err)
		}
	}()
	go func() {
		var tcp = packet.Make(0, s.MTU())

		for {
			err := raw.Read(context.Background(), tcp.SetHead(0))
			if errors.Is(err, io.EOF) {
				return
			}
			require.NoError(t, err)

			tcp.SetHead(64)
			test.ValidIP(t, tcp.Bytes())

			err = c.DecryptRaw(tcp)
			require.NoError(t, err)

			test.ValidIP(t, tcp.Bytes())

			s.Inbound(tcp)
		}
	}()
}
