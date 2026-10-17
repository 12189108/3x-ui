// Package session provides session management utilities for the 3x-ui web panel.
// It handles user authentication state, login sessions, and session storage using Gin sessions.
package session

import (
	"encoding/gob"
	"net/http"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUserKey  = "LOGIN_USER"
	loginEpochKey = "LOGIN_EPOCH"
	defaultPath   = "/"
)

func init() {
	gob.Register(model.User{})
}

// SetLoginUser stores only the user ID and revocation version in the cookie.
func SetLoginUser(c *gin.Context, user *model.User) {
	if user == nil {
		return
	}
	s := sessions.Default(c)
	s.Clear()
	s.Set(loginUserKey, user.Id)
	s.Set(loginEpochKey, user.LoginEpoch)
}

// SetMaxAge configures the session cookie maximum age in seconds.
// This controls how long the session remains valid before requiring re-authentication.
func SetMaxAge(c *gin.Context, maxAge int) {
	s := sessions.Default(c)
	s.Options(sessions.Options{
		Path:     defaultPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetLoginUser retrieves the authenticated user from the session.
// Returns nil if no user is logged in or if the session data is invalid.
func GetLoginUser(c *gin.Context) *model.User {
	s := sessions.Default(c)
	obj := s.Get(loginUserKey)
	if obj == nil {
		return nil
	}
	id, ok := obj.(int)
	epoch, hasEpoch := s.Get(loginEpochKey).(int64)
	// Legacy cookies contain a full User, including a password hash. Reject them.
	if !ok || !hasEpoch || id <= 0 {
		s.Clear()
		return nil
	}
	db := database.GetDB()
	if db == nil {
		return nil
	}
	user := &model.User{}
	if err := db.First(user, id).Error; err != nil || user.LoginEpoch != epoch {
		s.Clear()
		return nil
	}
	return user
}

// IsLogin checks if a user is currently authenticated in the session.
// Returns true if a valid user session exists, false otherwise.
func IsLogin(c *gin.Context) bool {
	return GetLoginUser(c) != nil
}

// ClearSession removes all session data and invalidates the session.
// This effectively logs out the user and clears any stored session information.
func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Options(sessions.Options{
		Path:     defaultPath,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
