package gateway

import (
	"context"
	"fmt"

	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	rbacstore "api-gateway/pkg/rbac/store"
	userstore "api-gateway/pkg/user/store"

	"github.com/spf13/cobra"
)

func migrateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations and seed default data",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			log.Infow("running RBAC module migrations")
			if err := rbacstore.RunMigrations(dsn); err != nil {
				return fmt.Errorf("rbac migrations: %w", err)
			}

			dbCfg := userstore.DBConfig{
				DSN:                    dsn,
				MaxOpenConns:           1,
				MaxIdleConns:           1,
				ConnMaxLifetimeMinutes: 1,
			}
			db, err := userstore.NewDB(context.Background(), dbCfg)
			if err != nil {
				return fmt.Errorf("connect to db for seed: %w", err)
			}

		ctx := context.Background()

		adminPath := "/admin"
		if cfg.RBAC != nil && cfg.RBAC.AdminPath != "" {
			adminPath = cfg.RBAC.AdminPath
		}

		log.Infow("seeding user module bootstrap data")
		if err := userstore.Seed(ctx, db); err != nil {
			return fmt.Errorf("user seed: %w", err)
		}

		log.Infow("seeding RBAC bootstrap data")
		if err := rbacstore.Seed(ctx, db, adminPath); err != nil {
			return fmt.Errorf("rbac seed: %w", err)
		}

			log.Infow("migrate completed successfully")
			return nil
		},
	}
}
