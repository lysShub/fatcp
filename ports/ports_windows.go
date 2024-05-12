package ports

import "syscall"

func setFilterAll(conn interface {
	SyscallConn() (syscall.RawConn, error)
}) error {
	panic("todo")
}
