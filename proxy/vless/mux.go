package vless

import (
	"context"
	"fmt"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	log "github.com/sirupsen/logrus"
)

// dialDispatcher is a minimal routing.Dispatcher that dials the real
// destination with net.Dial and bridges it to a transport.Link. It lets us
// reuse xray-core's common/mux ServerWorker (which only needs
// Dispatcher.Dispatch) for Mux.Cool demultiplexing without standing up a
// full xray-core instance.
type dialDispatcher struct{}

func (d *dialDispatcher) Type() interface{} { return nil }
func (d *dialDispatcher) Start() error      { return nil }
func (d *dialDispatcher) Close() error      { return nil }

// DispatchLink is unused by common/mux; stub it so we satisfy routing.Dispatcher.
func (d *dialDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return fmt.Errorf("mux dialDispatcher does not support DispatchLink")
}

// Dispatch opens a real connection to dest and returns a Link whose:
//   - Reader yields bytes received FROM the target (downstream responses)
//   - Writer accepts bytes to be sent TO the target (upstream requests)
//
// Two goroutines bridge the Link to the underlying net.Conn.
func (d *dialDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	network := "tcp"
	if dest.Network == net.Network_UDP {
		network = "udp"
	}
	conn, err := stdnet.DialTimeout(network, dest.NetAddr(), 10*time.Second)
	if err != nil {
		return nil, err
	}

	// respR/respw: downstream (target -> session).  link.Reader feeds the worker.
	// reqR/reqw: upstream (session -> target).           link.Writer is fed by the worker.
	respR, respW := pipe.New()
	reqR, reqW := pipe.New()
	link := &transport.Link{Reader: respR, Writer: reqW}

	// target -> respW -> worker (responses)
	go func() {
		_ = buf.Copy(buf.NewReader(conn), respW)
		_ = conn.Close()
	}()
	// worker -> reqR -> target (requests)
	go func() {
		_ = buf.Copy(reqR, buf.NewWriter(conn))
		_ = conn.Close()
	}()

	return link, nil
}

// handleMux handles a VLESS CommandMux connection.
//
// After the VLESS header (version/uuid/addons/cmd), a Mux command carries NO
// port/address on the wire — the rest of the connection is a Mux.Cool frame
// stream. Each frame encodes its own target, so this single TCP connection is
// demultiplexed into many logical sessions by xray-core's mux.ServerWorker.
//
//   - initialData are any bytes read together with the VLESS header
//     (buf[curr:n]); they are the head of the first Mux frame and must be
//     fed back into the reader before the worker starts, or the first frame
//     would be lost.
//   - Traffic is still accounted at the conn level via the countingConn (c),
//     so per-user aggregate bytes are counted for free.
func (s *Server) handleMux(c stdnet.Conn, initialData []byte, uuid [16]byte) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed a buffered reader with the leftover handshake bytes so the first
	// Mux frame is parsed intact, then continue reading from the conn.
	first := buf.FromBytes(initialData)
	reader := &buf.BufferedReader{
		Reader: buf.NewReader(c),
		Buffer: buf.MultiBuffer{first},
	}
	writer := buf.NewWriter(c)
	link := &transport.Link{Reader: reader, Writer: writer}

	worker, err := mux.NewServerWorker(ctx, &dialDispatcher{}, link)
	if err != nil {
		log.Errorf("VLESS Mux worker init failed for %s: %v", c.RemoteAddr(), err)
		return
	}

	log.WithFields(log.Fields{
		"client": c.RemoteAddr(),
		"user":   s.users[uuid].Email,
	}).Infof("VLESS Mux tunnel established to %s", c.RemoteAddr())
	// Block until the Mux tunnel ends (client closes, or a fatal frame error).
	select {
	case <-ctx.Done():
	case <-worker.WaitClosed():
	}
	log.Infof("VLESS Mux tunnel closed for %s", c.RemoteAddr())
}
