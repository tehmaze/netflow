// +build freebsd openbsd

package main

func init() {
	// sysctl kern.ipc.maxsockbuf -> 2097152
	readBuffer = 2097152
}
