// Package database provides database initialization, migration, and management utilities
// for the 3x-ui panel using GORM with SQLite.
package database

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

const (
	defaultUsername = "admin"
	defaultPassword = "admin"
)

func initModels() error {
	models := []any{
		&model.User{},
		&model.Inbound{},
		&model.OutboundTraffics{},
		&model.Setting{},
		&model.InboundClientIps{},
		&xray.ClientTraffic{},
		&model.HistoryOfSeeders{},
	}
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("Error auto migrating model: %v", err)
			return err
		}
	}
	return nil
}

// initUser creates a default admin user if the users table is empty.
func initUser() error {
	empty, err := isTableEmpty("users")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}
	if empty {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(defaultPassword)

		if err != nil {
			log.Printf("Error hashing default password: %v", err)
			return err
		}

		user := &model.User{
			Username:         defaultUsername,
			Password:         hashedPassword,
			CredentialScheme: crypto.CredentialBcrypt,
		}
		return db.Create(user).Error
	}
	return nil
}

// Classify existing credentials before migrating plaintext. SHA-384 digests are
// irreversible; their plaintext is available only after a successful login.
// Run in one transaction so a failure cannot leave partially migrated users.
func runSeeders() error {
	return db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.HistoryOfSeeders{}).Where("seeder_name = ?", "UserPasswordHash").Count(&count).Error; err != nil {
			return err
		}
		var users []model.User
		if err := tx.Find(&users).Error; err != nil {
			return err
		}
		for _, user := range users {
			if user.CredentialScheme != "" {
				if user.CredentialScheme == crypto.CredentialBcrypt && crypto.IsBcryptHash(user.Password) ||
					user.CredentialScheme == crypto.CredentialSHA384 && crypto.IsSHA384Hash(user.Username) && crypto.IsSHA384Hash(user.Password) {
					continue
				}
				return fmt.Errorf("invalid credential format for user ID %d", user.Id)
			}
			updates := map[string]any{}
			switch {
			case crypto.IsBcryptHash(user.Password):
				updates["credential_scheme"] = crypto.CredentialBcrypt
			case crypto.IsSHA384Hash(user.Username) && crypto.IsSHA384Hash(user.Password):
				updates["credential_scheme"] = crypto.CredentialSHA384
			case count == 0:
				hash, err := crypto.HashPasswordAsBcrypt(user.Password)
				if err != nil {
					return fmt.Errorf("migrate credentials for user ID %d: %w", user.Id, err)
				}
				updates["password"] = hash
				updates["credential_scheme"] = crypto.CredentialBcrypt
				updates["login_epoch"] = gorm.Expr("login_epoch + 1")
			default:
				return fmt.Errorf("unrecognized credential format for user ID %d", user.Id)
			}
			if err := tx.Model(&user).Updates(updates).Error; err != nil {
				return err
			}
		}
		if count == 0 {
			return tx.Create(&model.HistoryOfSeeders{SeederName: "UserPasswordHash"}).Error
		}
		return nil
	})
}

// isTableEmpty returns true if the named table contains zero rows.
func isTableEmpty(tableName string) (bool, error) {
	var count int64
	err := db.Table(tableName).Count(&count).Error
	return count == 0, err
}

// InitDB sets up the database connection, migrates models, and runs seeders.
func InitDB(dbPath string) error {
	dir := path.Dir(dbPath)
	err := os.MkdirAll(dir, fs.ModePerm)
	if err != nil {
		return err
	}

	var gormLogger logger.Interface

	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	c := &gorm.Config{
		Logger: gormLogger,
	}
	db, err = gorm.Open(sqlite.Open(dbPath), c)
	if err != nil {
		return err
	}

	if err := initModels(); err != nil {
		return err
	}

	if err := initUser(); err != nil {
		return err
	}
	return runSeeders()
}

// CloseDB closes the database connection if it exists.
func CloseDB() error {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetDB returns the global GORM database instance.
func GetDB() *gorm.DB {
	return db
}

// IsNotFound checks if the given error is a GORM record not found error.
func IsNotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}

// IsSQLiteDB checks if the given file is a valid SQLite database by reading its signature.
func IsSQLiteDB(file io.ReaderAt) (bool, error) {
	signature := []byte("SQLite format 3\x00")
	buf := make([]byte, len(signature))
	_, err := file.ReadAt(buf, 0)
	if err != nil {
		return false, err
	}
	return bytes.Equal(buf, signature), nil
}

// Checkpoint performs a WAL checkpoint on the SQLite database to ensure data consistency.
func Checkpoint() error {
	// Update WAL
	err := db.Exec("PRAGMA wal_checkpoint;").Error
	if err != nil {
		return err
	}
	return nil
}

// ValidateSQLiteDB opens the provided sqlite DB path with a throw-away connection
// and runs a PRAGMA integrity_check to ensure the file is structurally sound.
// It does not mutate global state or run migrations.
func ValidateSQLiteDB(dbPath string) error {
	if _, err := os.Stat(dbPath); err != nil { // file must exist
		return err
	}
	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var res string
	if err := gdb.Raw("PRAGMA integrity_check;").Scan(&res).Error; err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("sqlite integrity check failed: " + res)
	}
	return nil
}
