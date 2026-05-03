package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	userstore "api-gateway/pkg/user/store"

	rbacstore "api-gateway/pkg/rbac/store"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func initSuperAdminCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init-super-admin <username>",
		Short: "Create a super admin user with a random password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			username := args[0]

			cfg := &config.Config{}
			if err := cfg.ReadConfig(cfgFile); err != nil {
				return fmt.Errorf("read config: %w", err)
			}
			config.Set(cfg)

			log.Init(log.ReadLogOptions())
			defer log.Sync()

			if cfg.User == nil || cfg.User.DB.DSN == "" {
				return fmt.Errorf("user.db.dsn is required in config")
			}

			dsn := cfg.User.DB.DSN

			dbCfg := userstore.DBConfig{
				DSN:                    dsn,
				MaxOpenConns:           1,
				MaxIdleConns:           1,
				ConnMaxLifetimeMinutes: 1,
			}
			db, err := userstore.NewDB(context.Background(), dbCfg)
			if err != nil {
				return fmt.Errorf("connect to db: %w", err)
			}

			ctx := context.Background()

			password, err := generatePassword(16)
			if err != nil {
				return fmt.Errorf("generate password: %w", err)
			}

			if err := createSuperAdmin(ctx, db, username, password); err != nil {
				return fmt.Errorf("create super admin: %w", err)
			}

			fmt.Fprintf(os.Stdout, "username: %s\n", username)
			fmt.Fprintf(os.Stdout, "password: %s\n", password)

			log.Infow("super admin user created", "username", username)
			return nil
		},
	}
}

func generatePassword(length int) (string, error) {
	bytes := make([]byte, length*2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(bytes)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}

func createSuperAdmin(ctx context.Context, db *gorm.DB, username, password string) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tenant userstore.Tenant
		if err := tx.Where("code = ?", userstore.SystemTenantCode).First(&tenant).Error; err != nil {
			return fmt.Errorf("system tenant not found (run migrate first): %w", err)
		}

		user := userstore.User{
			TenantID:    tenant.ID,
			Username:    username,
			DisplayName: "Super Admin",
			Status:      1,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "username"}},
			DoUpdates: clause.AssignmentColumns([]string{"display_name", "status"}),
		}).Omit("UUID").Create(&user).Error; err != nil {
			return fmt.Errorf("upsert super admin user: %w", err)
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		cred := userstore.UserCredential{
			UserID:       user.ID,
			TenantID:     tenant.ID,
			ProviderType: "password",
			Credential:   string(hash),
			Status:       1,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "tenant_id"}, {Name: "provider_type"}},
			DoUpdates: clause.AssignmentColumns([]string{"credential", "status"}),
		}).Create(&cred).Error; err != nil {
			return fmt.Errorf("create credential: %w", err)
		}

		var role rbacstore.Role
		if err := tx.Where("tenant_id = ? AND code = ?", tenant.ID, rbacstore.SystemAdminRoleCode).First(&role).Error; err != nil {
			return fmt.Errorf("system_admin role not found (run migrate first): %w", err)
		}

		ur := rbacstore.UserRole{
			UserID:   user.ID,
			RoleID:   role.ID,
			TenantID: tenant.ID,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error; err != nil {
			return fmt.Errorf("assign system_admin role: %w", err)
		}

		return nil
	})
}
