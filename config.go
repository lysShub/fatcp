package fatcp

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/pkg/errors"

	"github.com/lysShub/fatcp/crypto"
	"github.com/lysShub/rawsock"
)

type Config struct {
	Handshake Handshake

	MTU int

	RecvErrLimit int

	RawConnOpts []rawsock.Option

	PcapRawConnPath string
	PcapBuiltinPath string
}

func (c *Config) init(laddr netip.Addr) (err error) {
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

// Handshake application layer handshake and swap secret key,
// if return crypto.Key{} means not encrypt.
//
// Client or Server must transport some data!!!
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

func (h *NotCrypto) Client(_ context.Context, tcp net.Conn) (_ crypto.Key, err error) {
	_, err = tcp.Write([]byte("hello"))
	return
}
func (h *NotCrypto) Server(_ context.Context, tcp net.Conn) (_ crypto.Key, err error) {
	_, err = io.ReadFull(tcp, make([]byte, 5))
	return
}
func (h *NotCrypto) NotCrypto() {}

// Sign sign can't guarantee transport security
type Sign struct {
	Sign   []byte
	Parser func(context.Context, []byte) (crypto.Key, error)
}

func (t *Sign) Client(ctx context.Context, conn net.Conn) (crypto.Key, error) {
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

func calcMTU[A Attacher](config *Config) int {
	// 计算因fatcp封装导致的MSS的最大变化大小, 此处计算可能的最大开销
	var a A
	o := a.Overhead()
	o += 20 // faketcp
	_, ok := config.Handshake.(interface{ NotCrypto() })
	if !ok {
		o += crypto.Bytes
	}
	if config.MTU <= o {
		panic("too small mtu")
	}

	// todo: 可以优化, 在初始化ustack时设置真实的MTU, 然后握手完成后再动态修改ustack的mtu,
	//      确保其outbou出的数据包再被fatcp封装后不会超出mtu
	return config.MTU - o
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
