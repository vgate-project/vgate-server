package model

import "time"

// User represents a VLESS user
type User struct {
	ID       string    `json:"id"`        // UUID
	Email    string    `json:"email"`     // User identifier
	Level    int       `json:"level"`     // Level
	ExpireAt time.Time `json:"expire_at"` // Expiration time
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
