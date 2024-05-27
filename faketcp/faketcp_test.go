package faketcp_test

import (
	"net/netip"
	"testing"

	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/netkit/packet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
)

func Test_FakeTCP(t *testing.T) {
	var pseudoSum1 uint16 = 1111

	var f = faketcp.New(
		19986, 8080,
		faketcp.PseudoSum1(pseudoSum1),
	)

	var p = packet.Make(faketcp.Overhead, 16)

	f.AttachSend(p)
	require.Equal(t, 16+20, p.Data())
	test.ValidTCP(t, p.Bytes(), pseudoSum1)
	require.True(t, faketcp.Is(p.Bytes()))

	f.DetachRecv(p)
	require.False(t, faketcp.Is(p.Bytes()))
	require.Equal(t, 16, p.Data())
}

func Test_ToNot(t *testing.T) {

	var (
		laddr = netip.AddrPortFrom(test.RandIP(), test.RandPort())
		raddr = netip.AddrPortFrom(test.RandIP(), test.RandPort())
		psum1 = header.PseudoHeaderChecksum(
			header.TCPProtocolNumber,
			test.Address(laddr.Addr()), test.Address(raddr.Addr()),
			0,
		)
	)

	{
		tcp := packet.From(test.BuildTCPSync(t, laddr, raddr))
		test.ValidTCP(t, tcp.Bytes(), psum1)

		tcp = faketcp.ToNot(tcp)

		require.False(t, faketcp.Is(tcp.Bytes()))
		test.ValidTCP(t, tcp.Bytes(), psum1)
		require.Equal(t, laddr.Port(), header.TCP(tcp.Bytes()).SourcePort())
	}
}
