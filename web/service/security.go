package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xlzd/gotp"
	"gorm.io/gorm"
)

// Serialize credential and second-factor changes, including their validation.
var securitySettingsMu sync.Mutex

func readSetting(tx *gorm.DB, key string) (string, error) {
	var setting model.Setting
	err := tx.Where("key = ?", key).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultValueMap[key], nil
	}
	return setting.Value, err
}

func writeSetting(tx *gorm.DB, key, value string) error {
	var setting model.Setting
	err := tx.Where("key = ?", key).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return tx.Create(&model.Setting{Key: key, Value: value}).Error
	}
	if err != nil {
		return err
	}
	return tx.Model(&setting).Update("value", value).Error
}

func revokeSessions(tx *gorm.DB) error {
	return tx.Model(&model.User{}).Where("1 = 1").Update("login_epoch", gorm.Expr("login_epoch + 1")).Error
}

// A restored database may contain an epoch used by an earlier cookie. Give the
// restored users a fresh version instead of incrementing the backed-up value.
func rotateRestoredSessionEpochs() error {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	epoch := int64(binary.LittleEndian.Uint64(nonce[:])>>1) | 1
	return database.GetDB().Model(&model.User{}).Where("1 = 1").Update("login_epoch", epoch).Error
}

// VerifyTwoFactorCode rejects malformed secrets before calling gotp (which panics
// on invalid base32), and tolerates one adjacent 30-second clock window.
func VerifyTwoFactorCode(secret, code string) bool {
	if len(code) != 6 || len(secret) > 128 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	secret = strings.ToUpper(strings.TrimRight(secret, "="))
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(decoded) < 10 {
		return false
	}
	totp := gotp.NewDefaultTOTP(secret)
	now := time.Now().Unix()
	valid := 0
	for _, delta := range []int64{-30, 0, 30} {
		valid |= subtle.ConstantTimeCompare([]byte(totp.At(now+delta)), []byte(code))
	}
	return valid == 1
}

func requireTwoFactor(tx *gorm.DB, code string) error {
	enabled, err := readSetting(tx, "twoFactorEnable")
	if err != nil {
		return err
	}
	isEnabled, err := strconv.ParseBool(enabled)
	if err != nil {
		return err
	}
	if !isEnabled {
		return nil
	}
	secret, err := readSetting(tx, "twoFactorToken")
	if err != nil {
		return err
	}
	if !VerifyTwoFactorCode(secret, code) {
		return errors.New("invalid two-factor code")
	}
	return nil
}

func (s *SettingService) CheckTwoFactorCode(code string) error {
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		return requireTwoFactor(tx, code)
	})
}

// UpdateTwoFactor verifies the existing factor before disabling or replacing it,
// and requires proof of the new factor before enabling it. Both the settings and
// all session revocations commit together.
func (s *SettingService) UpdateTwoFactor(enabled bool, secret, code, newCode string) error {
	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := requireTwoFactor(tx, code); err != nil {
			return err
		}
		if enabled {
			secret = strings.ToUpper(strings.TrimSpace(secret))
			if !VerifyTwoFactorCode(secret, newCode) {
				return errors.New("invalid new two-factor secret or code")
			}
		} else {
			secret = ""
		}
		if err := writeSetting(tx, "twoFactorEnable", strconv.FormatBool(enabled)); err != nil {
			return err
		}
		if err := writeSetting(tx, "twoFactorToken", secret); err != nil {
			return err
		}
		return revokeSessions(tx)
	})
}

// Local administrative setters also revoke cookies, including CLI recovery.
func setSecuritySetting(key, value string) error {
	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		old, err := readSetting(tx, key)
		if err != nil || old == value {
			return err
		}
		if err := writeSetting(tx, key, value); err != nil {
			return err
		}
		return revokeSessions(tx)
	})
}

func (s *SettingService) ResetTwoFactor() error {
	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := writeSetting(tx, "twoFactorEnable", "false"); err != nil {
			return err
		}
		if err := writeSetting(tx, "twoFactorToken", ""); err != nil {
			return err
		}
		return revokeSessions(tx)
	})
}

// Local recovery for the optional static login key used by the SHA-384 fork.
func (s *SettingService) ResetLoginSecrets() error {
	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.User{}).Where("1 = 1").Update("login_secret", "").Error; err != nil {
			return err
		}
		return revokeSessions(tx)
	})
}
