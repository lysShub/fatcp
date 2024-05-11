//go:build linux
// +build linux

package gonet

import "golang.org/x/sys/unix"

var ErrConnectReset = unix.ECONNRESET
