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

type Listener[A Attacher] interface {
	MTU() int
	Overhead() int
	Accept() (Conn[A], error)
	AcceptCtx(ctx context.Context) (Conn[A], error)
	Addr() netip.AddrPort
	Close() error
}

var _ Listener[Attacher] = (*listener[Attacher])(nil)

// datagram conn
type Conn[A Attacher] interface {
	MTU() int
	Overhead() int
	BuiltinTCP(ctx context.Context) (tcp net.Conn, err error)
	Recv(ctx context.Context, atter A, payload *packet.Packet) (err error)
	Send(ctx context.Context, atter A, payload *packet.Packet) (err error)
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
	Close() error
}

var _ Conn[Attacher] = (*conn[Attacher])(nil)
