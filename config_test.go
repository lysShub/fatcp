package fatcp

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_NotCrypto(t *testing.T) {
	var (
		caddr        = netip.AddrPortFrom(test.LocIP(), 19986)
		saddr        = netip.AddrPortFrom(test.LocIP(), 8080)
		serverConfig = &Config{
			Handshake:       &NotCrypto{},
			MTU:             1500,
			RecvErrLimit:    8,
			BuiltinPcapFile: "builtin-server.pcap",
		}
		clientConfig = &Config{
			Handshake:       &NotCrypto{},
			MTU:             1500,
			RecvErrLimit:    8,
			BuiltinPcapFile: "builtin-client.pcap",
		}
	)
	os.Remove("builtin-server.pcap")
	os.Remove("builtin-client.pcap")

	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber,
		caddr, saddr,
		test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
	)
	eg, ctx := errgroup.WithContext(context.Background())

	// echo server
	eg.Go(func() error {
		l, err := NewListener[Mocker](test.NewMockListener(t, s), serverConfig)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.From(make([]byte, serverConfig.MTU))
			var atter = &mocker{}

			err := conn.Recv(atter, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		_, err = io.Copy(tcp, tcp)
		require.Contains(t, []error{io.EOF, nil}, err)
		return nil
	})

	// client
	eg.Go(func() error {
		conn, err := NewConn[Mocker](c, clientConfig)
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.Make(0, clientConfig.MTU)
			var atter = &mocker{}

			err := conn.Recv(atter, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		rander := rand.New(rand.NewSource(0))
		test.ValidPingPongConn(t, rander, tcp, 0xffff)

		return nil
	})

	eg.Wait()
}

func Test_MTU(t *testing.T) {
	var laddr = test.LocIP()

	var cfg = &Config{}
	err := cfg.init(laddr)
	require.NoError(t, err)

	ifs, err := net.Interfaces()
	require.NoError(t, err)
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		require.NoError(t, err)
		for _, addr := range addrs {
			ip, ok := addr.(*net.IPNet)
			if ok && ip.IP.To4() != nil && netip.AddrFrom4([4]byte(ip.IP.To4())) == laddr {
				require.Equal(t, ifi.MTU, cfg.MTU)
				return
			}
		}
	}
	t.Fatal("not found default nic")
}

func Test_BuiltinPcapFile(t *testing.T) {
	var (
		caddr        = netip.AddrPortFrom(test.LocIP(), 19986)
		saddr        = netip.AddrPortFrom(test.LocIP(), 8080)
		tmp, err     = os.MkdirTemp("", fmt.Sprintf("%d", time.Now().Unix()))
		clientPcap   = filepath.Join(tmp, "client.pcap")
		serverPcap   = filepath.Join(tmp, "server.pcap")
		serverConfig = &Config{
			Handshake:       &NotCrypto{},
			MTU:             1500,
			RecvErrLimit:    8,
			BuiltinPcapFile: clientPcap,
		}
		clientConfig = &Config{
			Handshake:       &NotCrypto{},
			MTU:             1500,
			RecvErrLimit:    8,
			BuiltinPcapFile: serverPcap,
		}
	)
	require.NoError(t, err)
	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber,
		caddr, saddr,
		test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
	)
	eg, ctx := errgroup.WithContext(context.Background())

	// echo server
	eg.Go(func() error {
		l, err := NewListener[Mocker](test.NewMockListener(t, s), serverConfig)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.From(make([]byte, serverConfig.MTU))
			var atter = &mocker{}

			err := conn.Recv(atter, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		_, err = io.Copy(tcp, tcp)
		require.Contains(t, []error{io.EOF, nil}, err)
		return nil
	})

	// client
	eg.Go(func() error {
		conn, err := NewConn[Mocker](c, clientConfig)
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.Make(0, clientConfig.MTU)
			var atter = &mocker{}

			err := conn.Recv(atter, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		rander := rand.New(rand.NewSource(0))
		test.ValidPingPongConn(t, rander, tcp, 0xffff)

		return nil
	})
	eg.Wait()

	delta := filesize(t, clientPcap) - filesize(t, serverPcap)
	require.Less(t, int(-4e3), delta)
	require.Less(t, delta, int(4e3))
}

func filesize(t *testing.T, file string) int {
	fd, err := os.Open(file)
	require.NoError(t, err)
	info, err := fd.Stat()
	require.NoError(t, err)
	return int(info.Size())
}
