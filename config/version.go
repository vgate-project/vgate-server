package config

import (
	"fmt"
)

var (
	appName = "VGate-server"
	version = "dev"
	date    = "unknown"
)

func init() {
	fmt.Printf("%s %s, built at %s\n", appName, version, date)
}
