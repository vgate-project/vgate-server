package vless

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	Version = 0
	CmdTCP  = 1
	CmdUDP  = 2
	CmdMux  = 3 // VLESS Mux.Cool multiplexing command (xray RequestCommandMux = 0x03)

	AddrTypeIPv4   = 1
	AddrTypeDomain = 2
	AddrTypeIPv6   = 3
)

// MuxCoolAddress is the synthetic destination address xray-core uses for a
// VLESS Mux command. The wire format carries no real target after the command
// byte; the actual targets are encoded per-frame inside the Mux.Cool stream.
// Kept identical to xray-core (common/mux) so the dispatcher/targets align.
const MuxCoolAddress = "v1.mux.cool"

var (
	ErrInvalidVersion = errors.New("invalid vless version")
	ErrInvalidUUID    = errors.New("invalid user uuid")
	ErrInvalidCmd     = errors.New("invalid command")
	ErrInvalidAddr    = errors.New("invalid address type")
)

// ParseUUID converts a UUID string to 16 bytes
func ParseUUID(s string) ([16]byte, error) {
	var b [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return b, fmt.Errorf("invalid uuid length: %s", s)
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return b, err
	}
	copy(b[:], decoded)
	return b, nil
}
