package vless

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
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

func (d *dialDispatcher) Type() any    { return nil }
func (d *dialDispatcher) Start() error { return nil }
func (d *dialDispatcher) Close() error { return nil }

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
	var (
		reader buf.Reader
		writer buf.Writer
		closer io.Closer
	)

	if dest.Network == net.Network_UDP {
		// XUDP full-cone: bind an UNCONNECTED UDP socket so reply datagrams
		// from any source address are accepted. A connected UDP socket
		// (net.Dial("udp", dest)) would silently drop off-path replies,
		// which is exactly what STUN-style NAT detection sends — so full-cone
		// would fail. Outgoing datagrams are always sent to dest; reply
		// datagrams are stamped with their source address (b.UDP) so the
		// client's XUDPConn can reconstruct the full-cone mapping. This mirrors
		// xray-core's freedom outbound PacketReader.
		ua, err := stdnet.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		listenNet := "udp4"
		bind := &stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: 0}
		if ua.IP != nil && ua.IP.To4() == nil {
			listenNet = "udp6"
			bind = &stdnet.UDPAddr{IP: stdnet.IPv6zero, Port: 0}
		}
		pc, err := stdnet.ListenUDP(listenNet, bind)
		if err != nil {
			return nil, err
		}
		closer = pc
		reader = &udpPacketReader{conn: pc}
		writer = buf.NewWriter(&udpFullConeConn{conn: pc, dest: ua})
	} else {
		conn, err := stdnet.DialTimeout("tcp", dest.NetAddr(), 10*time.Second)
		if err != nil {
			return nil, err
		}
		closer = conn
		reader = buf.NewReader(conn)
		writer = buf.NewWriter(conn)
	}

	// respR/respw: downstream (target -> session).  link.Reader feeds the worker.
	// reqR/reqw: upstream (session -> target).           link.Writer is fed by the worker.
	respR, respW := pipe.New()
	reqR, reqW := pipe.New()
	link := &transport.Link{Reader: respR, Writer: reqW}

	// target -> respW -> worker (responses)
	go func() {
		_ = buf.Copy(reader, respW)
		_ = closer.Close()
	}()
	// worker -> reqR -> target (requests)
	go func() {
		_ = buf.Copy(reqR, writer)
		_ = closer.Close()
	}()

	return link, nil
}

// udpPacketReader reads datagrams from an unconnected UDP socket and stamps
// each buffer with the source address (b.UDP), mirroring xray-core's freedom
// outbound PacketReader. The client's XUDPConn needs b.UDP on replies to
// reconstruct the full-cone mapping; without it the reply framing carries no
// source and full-cone (and even normal XUDP) breaks.
type udpPacketReader struct {
	conn *stdnet.UDPConn
}

func (r *udpPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, d, err := r.conn.ReadFromUDP(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	if d != nil {
		b.UDP = &net.Destination{
			Address: net.IPAddress(d.IP),
			Port:    net.Port(d.Port),
			Network: net.Network_UDP,
		}
	}
	return buf.MultiBuffer{b}, nil
}

// udpFullConeConn adapts an unconnected *net.UDPConn to net.Conn so it can be
// used with buf.NewWriter. Writes always target the session destination; the
// socket stays unconnected so reply datagrams from any source are accepted
// (the full-cone behaviour XUDP relies on). It deliberately does NOT implement
// net.PacketConn, so buf.NewWriter uses the plain io.Writer path (Write).
type udpFullConeConn struct {
	conn *stdnet.UDPConn
	dest *stdnet.UDPAddr
}

func (c *udpFullConeConn) Read(b []byte) (int, error) {
	n, _, err := c.conn.ReadFromUDP(b)
	return n, err
}

func (c *udpFullConeConn) Write(b []byte) (int, error) {
	return c.conn.WriteToUDP(b, c.dest)
}

func (c *udpFullConeConn) Close() error                       { return c.conn.Close() }
func (c *udpFullConeConn) LocalAddr() stdnet.Addr             { return c.conn.LocalAddr() }
func (c *udpFullConeConn) RemoteAddr() stdnet.Addr            { return c.dest }
func (c *udpFullConeConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *udpFullConeConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *udpFullConeConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// handleMux handles a VLESS CommandMux connection.
//
// After the VLESS header (version/uuid/addons/cmd), a Mux command carries NO
// port/address on the wire — the rest of the connection is a Mux.Cool frame
// stream. Each frame encodes its own target, so this single TCP connection is
// demultiplexed into many logical sessions by xray-core's mux.ServerWorker.
//
//   - countingC is the countingConn used for traffic accounting on the
//     non-Vision path (and for writing the response header before this call).
//   - rawConn is the underlying *crypto/tls.Conn / *reality.Conn; Vision's
//     UnwrapRawConn must see this exact type, so it must NOT be the wrapped
//     countingConn when isVision is true.
//   - initialData are any bytes read together with the VLESS header
//     (buf[curr:n]); they are the head of the first Mux frame and must be
//     fed back into the reader before the worker starts, or the first frame
//     would be lost.
//   - isVision indicates the xtls-rprx-vision flow is in use. When true, the
//     entire Mux stream (which carries XUDP) is Vision-encoded by the client
//     and MUST be Vision-decoded here; otherwise the padding corrupts the Mux
//     frames and every session (notably UDP) inside the tunnel breaks.
func (s *Server) handleMux(countingC stdnet.Conn, rawConn stdnet.Conn, initialData []byte, uuid [16]byte, isVision bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		reader             buf.Reader
		writer             buf.Writer
		upCount, downCount buf.SizeCounter
	)

	if isVision {
		// Mirror handleTCPVision: wrap rawConn in the xray-recognized conn
		// type and apply the Vision reader/writer to the whole Mux stream.
		wrapped, input, rawInput, err := setupVisionConn(rawConn)
		if err != nil {
			log.Errorf("vision mux setup failed from %s: %v", rawConn.RemoteAddr(), err)
			return
		}
		trafficState := proxy.NewTrafficState(uuid[:])
		// Seed initialData then the raw Vision conn so the first Mux frame
		// (which may include the first Vision padding block) is intact.
		combined := io.MultiReader(bytes.NewReader(initialData), wrapped)
		visionReader := proxy.NewVisionReader(buf.NewReader(combined), trafficState, true, ctx, wrapped, input, rawInput, nil)
		visionWriter := proxy.NewVisionWriter(buf.NewWriter(wrapped), trafficState, false, ctx, wrapped, nil, nil)
		// Count Mux traffic at the buf layer: the countingConn cannot wrap the
		// raw conn (Vision needs the exact *tls.Conn/*reality.Conn type).
		reader = &sizeCountReader{Reader: visionReader, counter: &upCount}
		writer = &sizeCountWriter{Writer: visionWriter, counter: &downCount}
	} else {
		// Seed a buffered reader with the leftover handshake bytes so the
		// first Mux frame is parsed intact, then continue reading from conn.
		first := buf.FromBytes(initialData)
		reader = &buf.BufferedReader{
			Reader: buf.NewReader(countingC),
			Buffer: buf.MultiBuffer{first},
		}
		writer = buf.NewWriter(countingC)
	}

	link := &transport.Link{Reader: reader, Writer: writer}

	worker, err := mux.NewServerWorker(ctx, &dialDispatcher{}, link)
	if err != nil {
		log.Errorf("VLESS Mux worker init failed for %s: %v", countingC.RemoteAddr(), err)
		return
	}

	log.WithFields(log.Fields{
		"client": countingC.RemoteAddr(),
		"user":   s.users[uuid].Email,
		"vision": isVision,
	}).Infof("VLESS Mux tunnel established to %s", countingC.RemoteAddr())
	// Block until the Mux tunnel ends (client closes, or a fatal frame error).
	select {
	case <-ctx.Done():
	case <-worker.WaitClosed():
	}

	if isVision {
		s.addTraffic(uuid, upCount.Size, downCount.Size)
	}

	log.Infof("VLESS Mux tunnel closed for %s", countingC.RemoteAddr())
}

// sizeCountReader wraps a buf.Reader and tallies the bytes it yields. It is
// used to account traffic for the Vision Mux path, where the underlying conn
// cannot be wrapped by the countingConn.
type sizeCountReader struct {
	buf.Reader
	counter *buf.SizeCounter
}

func (r *sizeCountReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.counter.Size += int64(mb.Len())
	}
	return mb, err
}

// sizeCountWriter wraps a buf.Writer and tallies the bytes it accepts.
type sizeCountWriter struct {
	buf.Writer
	counter *buf.SizeCounter
}

func (w *sizeCountWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !mb.IsEmpty() {
		w.counter.Size += int64(mb.Len())
	}
	return w.Writer.WriteMultiBuffer(mb)
}
