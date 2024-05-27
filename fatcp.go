/*
	datagram transport connect on tcp, provide crypto option and builtin tcp.

*/

package fatcp

import (
	fconn "github.com/lysShub/fatun/conn"
)

var _ fconn.Listener = (*listener)(nil)

var _ fconn.Conn = (*conn)(nil)
