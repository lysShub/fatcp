package link

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/lysShub/netkit/packet"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func Test_Link(t *testing.T) {
	t.Skip("")

	seed := time.Now().UnixNano()
	s := rand.New(rand.NewSource(seed))
	t.Log("seed", seed)

	var ss []int
	for i := 0; i < 1024; i++ {
		ss = append(ss, s.Int()%0xff+64)
	}

	l := NewList(4, 32)

	go func() {
		time.Sleep(time.Second)
		for _, e := range ss {
			var pkts stack.PacketBufferList
			pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(make([]byte, e)),
			}))

			n, err := l.WritePackets(pkts)
			require.Equal(t, 1, n)
			require.Nil(t, err)

			time.Sleep(time.Millisecond)
		}
	}()

	var p = packet.Make(0, 0xff+64)

	for _, e := range ss {
		p.Sets(0, 0xff+64)

		err := l.Outbound(context.Background(), p)
		require.Nil(t, err)
		require.Equal(t, e, p.Data())
	}
}
