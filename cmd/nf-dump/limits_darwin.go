// +build darwin

package main

func init() {
	// On BSD/Darwin systems you need to add about a 15% padding to the
	// kernel limit socket buffer. Meaning if you want an 25MB buffer
	// (8388608 bytes) you need to set the kernel limit to 26214400*1.15 =
	// 30146560. This is not documented anywhere but happens in the kernel
	// https://github.com/freebsd/freebsd/blob/master/sys/kern/uipc_sockbuf.c
	readSize = 7130316
}
