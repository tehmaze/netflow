// +build linux

package main

import (
	"io/ioutil"
	"strconv"
)

func init() {
	// Attempt to read the actual limit from procfs and fail silently.
	b, err := ioutil.ReadFile("/proc/sys/net/core/rmem_max")
	if err == nil {
		readSize, err = strconv.Atoi(string(b))
	}
	if err != nil {
		// sysctl net.core.rmem_max -> 212992
		readSize = 212992
	}
}
