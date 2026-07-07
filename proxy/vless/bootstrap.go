package vless

// Anonymous imports register the built-in transports with the
// transport-registry via their package init() functions. Add a new import
// here to make an additional transport available to Server.
import (
	_ "github.com/vgate-project/vgate-server/transport/tcp"
	_ "github.com/vgate-project/vgate-server/transport/ws"
	_ "github.com/vgate-project/vgate-server/transport/xhttp"
)
