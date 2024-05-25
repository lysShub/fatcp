/*
	datagram transport connect on tcp, provide crypto option and builtin tcp.

	packet structure:

	{[fake tcp header] [attacher bytes] [payload]}

*/

package fatcp

import (
	"context"
	"net"
	"net/netip"

	"github.com/lysShub/netkit/packet"
)

type Listener interface {
	Accept() (Conn, error)
	AcceptCtx(ctx context.Context) (Conn, error)
	MTU() int
	Addr() netip.AddrPort
	Close() error
}

var _ Listener = (*listener)(nil)

// datagram conn
type Conn interface {
	BuiltinTCP(ctx context.Context) (tcp net.Conn, err error)
	Recv(ctx context.Context, atter Attacher, payload *packet.Packet) (err error)
	Send(ctx context.Context, atter Attacher, payload *packet.Packet) (err error)

	MTU() int
	Role() Role
	Overhead() int
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
	Close() error
}

var _ Conn = (*conn)(nil)
