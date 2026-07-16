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
	Up    int64  `json:"up"`   // Uploaded bytes since last report (delta)
	Down  int64  `json:"down"` // Downloaded bytes since last report (delta)
}
