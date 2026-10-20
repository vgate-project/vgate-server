package model

import "time"

// User represents a VLESS user
type User struct {
	ID       string    `json:"id"`        // UUID
	Email    string    `json:"email"`     // User identifier
	Level    int       `json:"level"`     // Level
	ExpireAt time.Time `json:"expire_at"` // Expiration time
	// SpeedLimitUpBps / SpeedLimitDownBps cap this user's upload / download
	// throughput in bytes/sec (0 = unlimited). The effective rate is min of
	// this and the node's global limit.
	SpeedLimitUpBps   int64 `json:"speed_limit_up_bps"`
	SpeedLimitDownBps int64 `json:"speed_limit_down_bps"`
}

// UserTraffic represents an incremental (delta) traffic report for a user.
// Up and Down are the number of bytes transferred SINCE the last successful
// report, not cumulative totals. The admin frontend is responsible for
// aggregating these increments to obtain total usage.
type UserTraffic struct {
	Email string `json:"email"`
	// NodeID is the entry point the traffic was measured on (a virtual child
	// of this node, matched by Reality short ID); empty means this node.
	NodeID string `json:"node_id,omitempty"`
	Up     int64  `json:"up"`   // Uploaded bytes since last report (delta)
	Down   int64  `json:"down"` // Downloaded bytes since last report (delta)
}

// UserUsage is a per-user accounting snapshot pulled from the manager's
// GET /server/usage: the effective traffic cap (base plan + bonus pool,
// -1 = unlimited) and the manager-side used total at snapshot time. The node
// adds its own un-reported bytes on top and enforces the cap locally; the
// manager's /users quota filter remains the authoritative gate.
type UserUsage struct {
	Email      string `json:"email"`
	QuotaBytes int64  `json:"quota_bytes"` // -1 = unlimited
	UsedBytes  int64  `json:"used_bytes"`
}
