package ustack_test

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func UnicomStackAndRaw(t *testing.T, s ustack.Ustack, raw rawsock.RawConn) {
	go func() {
		var pkt = packet.Make(64, s.MTU())

		for {
			s.Outbound(context.Background(), pkt.SetHead(64))
			if pkt.Data() == 0 {
				return
			}

			err := raw.Write(context.Background(), pkt)
			require.NoError(t, err)

			if debug.Debug() {
				pkt.SetHead(64)
				test.ValidIP(t, pkt.Bytes())
			}
		}
	}()
	go func() {
		var pkt = packet.Make(64, s.MTU())

		for {
			err := raw.Read(context.Background(), pkt.SetHead(64))
			if errors.Is(err, io.EOF) {
				return
			}
			require.NoError(t, err)

			pkt.SetHead(64)
			test.ValidIP(t, pkt.Bytes())

			s.Inbound(pkt)
		}
	}()
}

func UnicomStackAndRawBy(t *testing.T, s ustack.Ustack, raw rawsock.RawConn, dst netip.AddrPort) {
	go func() {
		var p = packet.Make(64, s.MTU())

		for {
			s.OutboundBy(context.Background(), dst, p.SetHead(64))
			if p.Data() == 0 {
				return
			}

			err := raw.Write(context.Background(), p)
			require.NoError(t, err)

			if debug.Debug() {
				p.SetHead(64)
				test.ValidIP(t, p.Bytes())
			}
		}
	}()
	go func() {
		var p = packet.Make(64, s.MTU())

		for {
			err := raw.Read(context.Background(), p.SetHead(64))
			if errors.Is(err, io.EOF) {
				return
			}
			require.NoError(t, err)

			p.SetHead(64)
			test.ValidIP(t, p.Bytes())

			s.Inbound(p)
		}
	}()
}
