//go:build windows
// +build windows

package gonet

import (
	"golang.org/x/sys/windows"
)

var ErrConnectReset = windows.WSAECONNRESET
