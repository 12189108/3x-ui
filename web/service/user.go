package service

import (
	"errors"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	ldaputil "github.com/mhsanaei/3x-ui/v2/util/ldap"
	"gorm.io/gorm"
)

// UserService provides business logic for user management and authentication.
// It handles user creation, login, password management, and 2FA operations.
type UserService struct {
	settingService SettingService
}

// GetFirstUser retrieves the first user from the database.
// This is typically used for initial setup or when there's only one admin user.
func (s *UserService) GetFirstUser() (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		First(user).
		Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) CheckUser(username string, password string, twoFactorCode string) *model.User {
	db := database.GetDB()

	user := &model.User{}

	err := db.Model(model.User{}).
		Where("username = ?", username).
		First(user).
		Error
	if err == gorm.ErrRecordNotFound {
		return nil
	} else if err != nil {
		logger.Warning("check user err:", err)
		return nil
	}

	// If LDAP enabled and local password check fails, attempt LDAP auth
	if !crypto.CheckPasswordHash(user.Password, password) {
		ldapEnabled, _ := s.settingService.GetLdapEnable()
		if !ldapEnabled {
			return nil
		}

		host, _ := s.settingService.GetLdapHost()
		port, _ := s.settingService.GetLdapPort()
		useTLS, _ := s.settingService.GetLdapUseTLS()
		bindDN, _ := s.settingService.GetLdapBindDN()
		ldapPass, _ := s.settingService.GetLdapPassword()
		baseDN, _ := s.settingService.GetLdapBaseDN()
		userFilter, _ := s.settingService.GetLdapUserFilter()
		userAttr, _ := s.settingService.GetLdapUserAttr()

		cfg := ldaputil.Config{
			Host:       host,
			Port:       port,
			UseTLS:     useTLS,
			BindDN:     bindDN,
			Password:   ldapPass,
			BaseDN:     baseDN,
			UserFilter: userFilter,
			UserAttr:   userAttr,
		}
		ok, err := ldaputil.AuthenticateUser(cfg, username, password)
		if err != nil || !ok {
			return nil
		}
		// On successful LDAP auth, continue 2FA checks below
	}

	twoFactorEnable, err := s.settingService.GetTwoFactorEnable()
	if err != nil {
		logger.Warning("check two factor err:", err)
		return nil
	}

	if twoFactorEnable {
		twoFactorToken, err := s.settingService.GetTwoFactorToken()

		if err != nil {
			logger.Warning("check two factor token err:", err)
			return nil
		}

		if !VerifyTwoFactorCode(twoFactorToken, twoFactorCode) {
			return nil
		}
	}

	return user
}

func (s *UserService) UpdateUser(id int, username string, password string, twoFactorCode string) error {
	db := database.GetDB()
	hashedPassword, err := crypto.HashPasswordAsBcrypt(password)

	if err != nil {
		return err
	}

	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	return db.Transaction(func(tx *gorm.DB) error {
		if err := requireTwoFactor(tx, twoFactorCode); err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
			"username": username, "password": hashedPassword,
			"login_epoch": gorm.Expr("login_epoch + 1"),
		}).Error
	})
}

func (s *UserService) UpdateFirstUser(username string, password string) error {
	if username == "" {
		return errors.New("username can not be empty")
	} else if password == "" {
		return errors.New("password can not be empty")
	}
	hashedPassword, er := crypto.HashPasswordAsBcrypt(password)

	if er != nil {
		return er
	}

	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).First(user).Error
	if database.IsNotFound(err) {
		user.Username = username
		user.Password = hashedPassword
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	return db.Model(user).Updates(map[string]any{
		"username": username, "password": hashedPassword,
		"login_epoch": gorm.Expr("login_epoch + 1"),
	}).Error
}
