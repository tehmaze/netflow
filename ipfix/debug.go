package ipfix

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

var debug = os.Getenv("NETFLOWDEBUG") != ""
var debugLog = log.New(os.Stderr, "ipfix: ", log.Lmicroseconds|log.Lmicroseconds)

func hexdump(data []byte) {
	fmt.Fprintf(os.Stderr, hex.Dump(data))
}
