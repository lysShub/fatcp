package fatcp

import (
	"context"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock"
)

func Dial(raw rawsock.RawConn, config *Config) (*Conn, error) {
	return DialCtx(context.Background(), raw, config)
}

func DialCtx(ctx context.Context, raw rawsock.RawConn, config *Config) (*Conn, error) {
	return dial(ctx, raw, config)
}

func dial(ctx context.Context, raw rawsock.RawConn, config *Config) (*Conn, error) {
	if err := config.Init(); err != nil {
		return nil, err
	}

	stack, err := ustack.NewUstack(
		link.NewList(8, config.MTU-Overhead),
		raw.LocalAddr().Addr(),
	)
	if err != nil {
		return nil, err
	}
	// stack = test.MustWrapPcap(fmt.Sprintf("client-ctr-%d.pcap", raw.LocalAddr().Port()), stack)

	ep, err := stack.LinkEndpoint(raw.LocalAddr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, err
	}

	conn, err := newConn(raw, ep, client, config)
	if err != nil {
		return nil, conn.close(err)
	}
	conn.factory = &clientFactory{
		local: conn.LocalAddr(), remote: conn.RemoteAddr(),
		stack: stack,
	}

	if err = conn.handshake(ctx); err != nil {
		return nil, conn.close(err)
	}
	return conn, nil
}
