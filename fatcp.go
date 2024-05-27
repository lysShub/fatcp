/*
	datagram transport connect on tcp, provide crypto option and builtin tcp.

*/

package fatcp

import (
	"fmt"

	fconn "github.com/lysShub/fatun/conn"
)

var _ fconn.Listener = (*listener)(nil)

var _ fconn.Conn = (*conn)(nil)

type role uint8

const (
	client role = 1
	server role = 2
)

func (r role) Client() bool { return r == client }
func (r role) Server() bool { return r == server }
func (r role) String() string {
	switch r {
	case client:
		return "client"
	case server:
		return "server"
	default:
		return fmt.Sprintf("invalid fatcp role %d", r)
	}
}
