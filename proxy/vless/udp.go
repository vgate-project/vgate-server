package vless

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// handleUDP implements the VLESS UDP-over-TCP relay.
//
// Datagrams are framed on the TCP side using a length-prefixed format:
// each datagram is preceded by a 2-byte big-endian length. initialData
// contains bytes already read after the VLESS header, which may include
// the first datagram(s).
func (s *Server) handleUDP(conn net.Conn, destAddr string, initialData []byte) {
	destConn, err := net.DialTimeout("udp", destAddr, 10*time.Second)
	if err != nil {
		log.Errorf("Failed to dial UDP destination %s: %v", destAddr, err)
		return
	}
	defer destConn.Close()

	errChan := make(chan error, 2)

	// TCP -> UDP
	go func() {
		reader := io.MultiReader(bytes.NewReader(initialData), conn)
		for {
			var length uint16
			if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
				errChan <- err
				return
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				errChan <- err
				return
			}
			if _, err := destConn.Write(payload); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// UDP -> TCP
	go func() {
		udpBuf := make([]byte, 2048)
		for {
			n, err := destConn.Read(udpBuf)
			if err != nil {
				errChan <- err
				return
			}
			lengthBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBuf, uint16(n))
			if _, err := conn.Write(lengthBuf); err != nil {
				errChan <- err
				return
			}
			if _, err := conn.Write(udpBuf[:n]); err != nil {
				errChan <- err
				return
			}
		}
	}()

	<-errChan
}
