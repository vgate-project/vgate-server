package vless

import (
	"net"

	"github.com/vgate-project/vgate-server/model"

	log "github.com/sirupsen/logrus"
)

// UpdateUsers replaces the current active user set with the provided list
// (hot-reload). All connections belonging to users that no longer exist in
// the new set are forcibly closed so that revoked users lose access
// immediately.
func (s *Server) UpdateUsers(users []model.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldUsers := s.users
	oldULimiters := s.userULimiters
	oldDLimiters := s.userDLimiters
	newUsers := make(map[[16]byte]model.User)
	newULimiters := make(map[[16]byte]*rateBucket)
	newDLimiters := make(map[[16]byte]*rateBucket)
	for _, u := range users {
		uuid, err := ParseUUID(u.ID)
		if err != nil {
			log.Errorf("Failed to parse UUID for user %s: %v", u.Email, err)
			continue
		}
		newUsers[uuid] = u
		// Reuse the existing bucket when the limit is unchanged so in-flight
		// connections keep their accrued burst; otherwise build a fresh one.
		if b, ok := oldULimiters[uuid]; ok && b != nil && b.rate == u.SpeedLimitUpBps {
			newULimiters[uuid] = b
		} else {
			newULimiters[uuid] = newRateBucket(u.SpeedLimitUpBps)
		}
		if b, ok := oldDLimiters[uuid]; ok && b != nil && b.rate == u.SpeedLimitDownBps {
			newDLimiters[uuid] = b
		} else {
			newDLimiters[uuid] = newRateBucket(u.SpeedLimitDownBps)
		}
	}
	s.users = newUsers
	s.userULimiters = newULimiters
	s.userDLimiters = newDLimiters
	log.Infof("VLESS users updated: %d users active", len(s.users))

	// Close connections for deleted users
	for uuid, user := range oldUsers {
		if _, ok := newUsers[uuid]; !ok {
			if conns, exists := s.userConns[uuid]; exists {
				log.Infof("Closing %d connections for removed user %s", len(conns), user.Email)
				for conn := range conns {
					conn.Close()
				}
				delete(s.userConns, uuid)
			}
			delete(s.userULimiters, uuid)
			delete(s.userDLimiters, uuid)
		}
	}
}

func (s *Server) addConn(uuid [16]byte, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userConns[uuid] == nil {
		s.userConns[uuid] = make(map[net.Conn]struct{})
	}
	s.userConns[uuid][conn] = struct{}{}
}

func (s *Server) removeConn(uuid [16]byte, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conns, ok := s.userConns[uuid]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(s.userConns, uuid)
		}
	}
}
