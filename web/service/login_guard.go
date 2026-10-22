package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const LoginRetryAfter = 2

var (
	ErrLoginBanned         = errors.New("IP permanently blocked")
	ErrLoginRateLimited    = errors.New("login rate limit exceeded")
	ErrLoginAttemptExpired = errors.New("login attempt expired or revoked")
	loginRequestRate       = rate.NewLimiter(10, 10)
	loginWorkers           = make(chan struct{}, 4)
)

func canonicalLoginIP(value string) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.IsUnspecified() {
		return "", errors.New("invalid login IP")
	}
	return ip.WithZone("").Unmap().String(), nil
}

func IsLoginIPBanned(value string) (bool, error) {
	ip, err := canonicalLoginIP(value)
	if err != nil {
		return false, err
	}
	var count int64
	err = database.GetDB().Model(&model.LoginGuard{}).Where("ip = ? AND banned = ?", ip, true).Count(&count).Error
	return count != 0, err
}

// A database lease admits only one attempt per IP, including across processes.
// A unique token prevents an expired or manually revoked attempt from logging in.
type LoginAttempt struct {
	ip, token string
	once      sync.Once
	banned    bool
	err       error
}

func (a *LoginAttempt) Validate() error {
	var count int64
	err := database.GetDB().Model(&model.LoginGuard{}).
		Where("ip = ? AND attempt_token = ? AND banned = ? AND lease_until > ?", a.ip, a.token, false, time.Now().UnixMilli()).Count(&count).Error
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrLoginAttemptExpired
	}
	return nil
}

func BeginLoginAttempt(value string) (*LoginAttempt, error) {
	ip, err := canonicalLoginIP(value)
	if err != nil {
		return nil, err
	}
	banned, err := IsLoginIPBanned(ip)
	if err != nil {
		return nil, err
	}
	if banned {
		return nil, ErrLoginBanned
	}
	if !loginRequestRate.Allow() {
		return nil, ErrLoginRateLimited
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	a := &LoginAttempt{ip: ip, token: hex.EncodeToString(nonce[:])}
	now := time.Now().UnixMilli()
	err = database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.LoginGuard{IP: ip}).Error; err != nil {
			return err
		}
		result := tx.Model(&model.LoginGuard{}).
			Where("ip = ? AND banned = ? AND next_attempt_at <= ? AND lease_until <= ?", ip, false, now, now).
			Updates(map[string]any{"next_attempt_at": now + LoginRetryAfter*1000, "lease_until": now + 60_000, "attempt_token": a.token})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			var guard model.LoginGuard
			if err := tx.First(&guard, "ip = ?", ip).Error; err != nil {
				return err
			}
			if guard.Banned {
				return ErrLoginBanned
			}
			return ErrLoginRateLimited
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Complete never clears failures on success. Only explicit local unbanning does.
// Call it before issuing a session, and defer Complete(false) for internal errors.
func (a *LoginAttempt) Complete(failed bool) (bool, error) {
	a.once.Do(func() {
		a.err = database.GetDB().Transaction(func(tx *gorm.DB) error {
			updates := map[string]any{"attempt_token": "", "lease_until": 0}
			if failed {
				updates["failures"] = gorm.Expr("failures + 1")
				updates["banned"] = gorm.Expr("CASE WHEN failures + 1 >= 3 THEN 1 ELSE 0 END")
			}
			result := tx.Model(&model.LoginGuard{}).
				Where("ip = ? AND attempt_token = ? AND banned = ? AND lease_until > ?", a.ip, a.token, false, time.Now().UnixMilli()).Updates(updates)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrLoginAttemptExpired
			}
			var guard model.LoginGuard
			if err := tx.First(&guard, "ip = ?", a.ip).Error; err != nil {
				return err
			}
			a.banned = guard.Banned
			return nil
		})
	})
	return a.banned, a.err
}

func AcquireLoginWorker() (func(), error) {
	select {
	case loginWorkers <- struct{}{}:
		return func() { <-loginWorkers }, nil
	default:
		return nil, ErrLoginRateLimited
	}
}

func UnbanLoginIP(value string) error {
	ip, err := canonicalLoginIP(value)
	if err != nil {
		return err
	}
	// Deletion also revokes any in-flight token. A stale request cannot recreate it.
	return database.GetDB().Where("ip = ?", ip).Delete(&model.LoginGuard{}).Error
}

func ListBannedLoginIPs() ([]model.LoginGuard, error) {
	var guards []model.LoginGuard
	err := database.GetDB().Where("banned = ?", true).Order("ip").Find(&guards).Error
	return guards, err
}
