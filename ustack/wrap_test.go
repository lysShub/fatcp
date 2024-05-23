package ustack_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_WrapConn(t *testing.T) {
	var (
		caddr      = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		saddr      = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		seed       = time.Now().UnixNano()
		r          = rand.New(rand.NewSource(seed))
		tmp, err   = os.MkdirTemp("", fmt.Sprintf("%d", time.Now().Unix()))
		clientPcap = filepath.Join(tmp, "client.pcap")
		serverPcap = filepath.Join(tmp, "server.pcap")
	)
	require.NoError(t, err)

	t.Log("seed", seed)
	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber,
		caddr, saddr,
		test.ValidAddr, test.ValidChecksum,
	)
	eg, _ := errgroup.WithContext(context.Background())

	eg.Go(func() error {
		st, err := ustack.NewUstack(link.NewList(16, 1536), saddr.Addr())
		require.NoError(t, err)
		st = ustack.MustWrapPcap(st, serverPcap)
		UnicomStackAndRaw(t, st, s)

		l, err := gonet.ListenTCP(st, saddr, header.IPv4ProtocolNumber)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept(context.Background())
		require.NoError(t, err)
		defer conn.Close()

		_, err = io.Copy(conn, conn)
		if errors.Is(err, gonet.ErrConnectReset) {
			return nil
		}
		return err
	})

	eg.Go(func() error {
		time.Sleep(time.Second)
		st, err := ustack.NewUstack(link.NewList(16, 1536), caddr.Addr())
		require.NoError(t, err)
		st = ustack.MustWrapPcap(st, clientPcap)
		UnicomStackAndRaw(t, st, c)

		conn, err := gonet.DialTCPWithBind(
			context.Background(), st,
			caddr, saddr,
			header.IPv4ProtocolNumber,
		)
		require.NoError(t, err)
		defer conn.Close()

		test.ValidPingPongConn(t, r, conn, 0xffff)

		return nil
	})
	require.NoError(t, eg.Wait())

	delta := filesize(t, clientPcap) - filesize(t, serverPcap)
	require.Less(t, -4e3, delta)
	require.Less(t, delta, 4e3)
}

func filesize(t *testing.T, file string) int {
	fd, err := os.Open(file)
	require.NoError(t, err)
	info, err := fd.Stat()
	require.NoError(t, err)
	return int(info.Size())
}
