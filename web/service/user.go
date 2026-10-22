package service

import (
	"crypto/subtle"
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

// MatchLocalCredentials accepts plaintext input only, including for legacy hashes.
func MatchLocalCredentials(user *model.User, username, password string) bool {
	if user.CredentialScheme == crypto.CredentialSHA384 {
		return crypto.CheckSHA384Hash(user.Username, username) && crypto.CheckSHA384Hash(user.Password, password)
	}
	return user.Username == username && crypto.CheckPasswordHash(user.Password, password)
}

func (s *UserService) HasLoginSecret() (bool, error) {
	var count int64
	err := database.GetDB().Model(&model.User{}).Where("login_secret <> ''").Count(&count).Error
	return count > 0, err
}

func (s *UserService) CheckUser(username string, password string, twoFactorCode string, loginSecret ...string) *model.User {
	user, _ := s.AuthenticateUser(username, password, twoFactorCode, loginSecret...)
	return user
}

var ErrInvalidCredentials = errors.New("invalid credentials")

// Authentication failures are distinct from internal errors: outages must not
// consume the three failures that permanently ban an IP.
func (s *UserService) AuthenticateUser(username string, password string, twoFactorCode string, loginSecret ...string) (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}

	err := db.Model(model.User{}).
		Where("username = ? AND credential_scheme <> ?", username, crypto.CredentialSHA384).
		First(user).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = db.Where("credential_scheme = ? AND LOWER(username) = ?", crypto.CredentialSHA384, crypto.SHA384Hash(username)).First(user).Error
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrInvalidCredentials
	} else if err != nil {
		logger.Warning("check user err:", err)
		return nil, err
	}

	// If LDAP enabled and local password check fails, attempt LDAP auth
	if !MatchLocalCredentials(user, username, password) {
		if user.CredentialScheme == crypto.CredentialSHA384 {
			return nil, ErrInvalidCredentials
		}
		ldapEnabled, err := s.settingService.GetLdapEnable()
		if err != nil {
			return nil, err
		}
		if !ldapEnabled {
			return nil, ErrInvalidCredentials
		}

		readString := func(get func() (string, error)) string {
			if err != nil {
				return ""
			}
			var value string
			value, err = get()
			return value
		}
		host := readString(s.settingService.GetLdapHost)
		port, portErr := s.settingService.GetLdapPort()
		if portErr != nil {
			return nil, portErr
		}
		useTLS, tlsErr := s.settingService.GetLdapUseTLS()
		if tlsErr != nil {
			return nil, tlsErr
		}
		bindDN := readString(s.settingService.GetLdapBindDN)
		ldapPass := readString(s.settingService.GetLdapPassword)
		baseDN := readString(s.settingService.GetLdapBaseDN)
		userFilter := readString(s.settingService.GetLdapUserFilter)
		userAttr := readString(s.settingService.GetLdapUserAttr)
		if err != nil {
			return nil, err
		}

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
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidCredentials
		}
		// On successful LDAP auth, continue 2FA checks below
	}

	providedSecret := ""
	if len(loginSecret) > 0 {
		providedSecret = loginSecret[0]
	}
	if user.LoginSecret != "" && subtle.ConstantTimeCompare([]byte(user.LoginSecret), []byte(providedSecret)) != 1 {
		return nil, ErrInvalidCredentials
	}

	securitySettingsMu.Lock()
	defer securitySettingsMu.Unlock()
	err = db.Transaction(func(tx *gorm.DB) error {
		var current model.User
		if err := tx.First(&current, user.Id).Error; err != nil {
			return err
		}
		if current.Username != user.Username || current.Password != user.Password || current.LoginEpoch != user.LoginEpoch || current.LoginSecret != user.LoginSecret || current.CredentialScheme != user.CredentialScheme {
			return errors.New("credentials changed during login")
		}
		if err := requireTwoFactor(tx, twoFactorCode); err != nil {
			return err
		}
		if current.CredentialScheme == crypto.CredentialSHA384 {
			var duplicates int64
			if err := tx.Model(&model.User{}).Where("id <> ? AND username = ?", current.Id, username).Count(&duplicates).Error; err != nil {
				return err
			}
			if duplicates != 0 {
				return errors.New("username conflicts with an existing account")
			}
			hash, err := crypto.HashPasswordAsBcrypt(password)
			if err != nil {
				return err
			}
			current.Username = username
			current.Password = hash
			current.CredentialScheme = crypto.CredentialBcrypt
			current.LoginEpoch++
			if err := tx.Model(&current).Updates(map[string]any{
				"username": current.Username, "password": current.Password,
				"credential_scheme": current.CredentialScheme, "login_epoch": current.LoginEpoch,
			}).Error; err != nil {
				return err
			}
		}
		*user = current
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidTwoFactorCode) {
			return nil, ErrInvalidCredentials
		}
		logger.Warning("login validation or credential migration failed:", err)
		return nil, err
	}
	return user, nil
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
			"credential_scheme": crypto.CredentialBcrypt,
			"login_epoch":       gorm.Expr("login_epoch + 1"),
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
		user.CredentialScheme = crypto.CredentialBcrypt
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	return db.Model(user).Updates(map[string]any{
		"username": username, "password": hashedPassword,
		"credential_scheme": crypto.CredentialBcrypt,
		"login_epoch":       gorm.Expr("login_epoch + 1"),
	}).Error
}
