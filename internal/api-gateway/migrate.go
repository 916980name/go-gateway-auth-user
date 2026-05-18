package gateway

import (
	"context"
	"fmt"
	"time"

	"api-gateway/pkg/config"
	"api-gateway/pkg/log"

	rbacstore "go-user-manage/pkg/rbac/store"
	userstore "go-user-manage/pkg/user/store"

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

			if cfg.Perm == nil || cfg.Perm.DB.DSN == "" {
				return fmt.Errorf("perm.db.dsn is required in config")
			}

			dsn := cfg.Perm.DB.DSN

			log.Infow("running database migrations")
			if err := rbacstore.RunMigrations(dsn); err != nil {
				return fmt.Errorf("migrations: %w", err)
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
			sqlDB, _ := db.DB()
			defer sqlDB.Close()
			sqlDB.SetConnMaxLifetime(time.Minute)

			ctx := context.Background()

			log.Infow("seeding user module bootstrap data")
			if err := userstore.Seed(ctx, db); err != nil {
				return fmt.Errorf("user seed: %w", err)
			}

			log.Infow("seeding RBAC bootstrap data")
			if err := rbacstore.Seed(ctx, db, "/admin"); err != nil {
				return fmt.Errorf("rbac seed: %w", err)
			}

			log.Infow("migrate completed successfully")
			return nil
		},
	}
}
