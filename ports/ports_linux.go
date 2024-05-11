package ports

import (
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func setFilterAll(conn interface {
	SyscallConn() (syscall.RawConn, error)
}) error {

	if raw, err := conn.SyscallConn(); err != nil {
		return err
	} else {
		var e error
		err = raw.Control(func(fd uintptr) {
			var rawIns []bpf.RawInstruction
			if rawIns, e = bpf.Assemble([]bpf.Instruction{
				bpf.RetConstant{Val: 0},
			}); e != nil {
				return
			}
			prog := &unix.SockFprog{
				Len:    uint16(len(rawIns)),
				Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
			}
			e = unix.SetsockoptSockFprog(
				int(fd), unix.SOL_SOCKET,
				unix.SO_ATTACH_FILTER, prog,
			)
		})
		if err != nil {
			return err
		} else if e != nil {
			return e
		}
	}
	return nil
}
