package fatcp

import (
	"context"
	"encoding/gob"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/fatcp/crypto"
)

type Config struct {
	Handshake Handshake

	// fatun read from rawsock.RawConn with MaxRecvBuffSize bytes capacity,
	// RawConn will merge MF ip packet automaticly, so mss possible greater than mtu sometimes.
	// generally set it to mtu is sufficient.
	MaxRecvBuffSize int

	// only use by gvisor LinkEndpoint
	MTU int

	RecvErrLimit int
}

func (c *Config) Init() error {
	if c == nil {
		panic("nil config")
	}

	if c.MaxRecvBuffSize <= 0 {
		c.MaxRecvBuffSize = 1536
	}
	if c.MTU <= 0 {
		c.MTU = 1360
	}
	if c.RecvErrLimit == 0 {
		c.RecvErrLimit = 8
	}
	return nil
}

// Handshake if return crypto.Key{} means not encrypt
type Handshake interface {
	Client(ctx context.Context, tcp net.Conn) (crypto.Key, error)
	Server(ctx context.Context, tcp net.Conn) (crypto.Key, error)
}

type ErrOverflowMTU int

func (e ErrOverflowMTU) Error() string {
	return fmt.Sprintf("packet size %d overflow mtu limit", int(e))
}
func (ErrOverflowMTU) Temporary() bool { return true }

// Sign sign can't guarantee transport security
type Sign struct {
	Sign   []byte
	Parser Parser
}

type Parser func(context.Context, []byte) (crypto.Key, error)

func (t *Sign) Client(ctx context.Context, conn net.Conn) (crypto.Key, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	key, err := t.Parser(ctx, t.Sign)
	if err != nil {
		return crypto.Key{}, err
	}

	err = gob.NewEncoder(conn).Encode(t.Sign)
	if err != nil {
		select {
		case <-ctx.Done():
			return crypto.Key{}, errors.WithStack(err)
		default:
			return crypto.Key{}, err
		}
	}

	return key, nil
}

func (t *Sign) Server(ctx context.Context, conn net.Conn) (crypto.Key, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	var sign []byte
	err := gob.NewDecoder(conn).Decode(&sign)
	if err != nil {
		select {
		case <-ctx.Done():
			return crypto.Key{}, errors.WithStack(ctx.Err())
		default:
			return crypto.Key{}, errors.WithStack(err)
		}
	}

	return t.Parser(ctx, sign)
}
