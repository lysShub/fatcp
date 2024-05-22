package fatcp

import (
	"context"
	"encoding/gob"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/fatcp/crypto"
)

type Config struct {
	Handshake Handshake

	MTU int

	RecvErrLimit int

	BuiltinPcapFile string
}

func (c *Config) Init(laddr netip.Addr) (err error) {
	if c == nil {
		panic("nil config")
	}

	if c.Handshake == nil {
		c.Handshake = &NotCrypto{}
	}

	if c.MTU == 0 {
		if i, err := ifaceByAddr(laddr); err != nil {
			return err
		} else {
			c.MTU = i.MTU
		}
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

type NotCrypto struct{}

func (h *NotCrypto) Client(context.Context, net.Conn) (_ crypto.Key, _ error) { return }
func (h *NotCrypto) Server(context.Context, net.Conn) (_ crypto.Key, _ error) { return }

// Sign sign can't guarantee transport security
type Sign struct {
	Sign   []byte
	Parser func(context.Context, []byte) (crypto.Key, error)
}

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

// todo: optimzie
func ifaceByAddr(laddr netip.Addr) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagRunning == 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		for _, addr := range addrs {
			if e, ok := addr.(*net.IPNet); ok && e.IP.To4() != nil {
				if netip.AddrFrom4([4]byte(e.IP.To4())) == laddr {
					return &i, nil
				}
			}
		}
	}

	return nil, errors.Errorf("not found adapter %s mtu", laddr.String())
}
