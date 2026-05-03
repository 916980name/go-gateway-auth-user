package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"api-gateway/pkg/auth"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/rbac"
	"api-gateway/pkg/user"
	"api-gateway/pkg/verflag"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	_ "go.uber.org/automaxprocs"
)

var (
	cfgFile  string
	limitCpu int
)

func NewCommand() *cobra.Command {
	log.Debugw("NewCommand begin")
	cmd := &cobra.Command{
		Use:          "api-gateway",
		Short:        "A good Go practical project",
		Long:         `A good Go practical project, used to create user with basic information.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			cfg := &config.Config{}
			err := cfg.ReadConfig(cfgFile)
			if err != nil {
				log.Errorw("start failed", "error", err)
				return err
			}
			config.Set(cfg)

			log.Init(log.ReadLogOptions())
			defer log.Sync()

			log.Debugw("NewCommand cobra ready to run")
			return run()
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}

			return nil
		},
	}

	log.Debugw("NewCommand cobra oninit")

	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "The path to the blog configuration file. Empty string for no configuration file.")
	cmd.PersistentFlags().IntVar(&limitCpu, "cpu", 0, "The limit using cpu core")

	cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	cmd.AddCommand(caCertCommand())
	cmd.AddCommand(migrateCommand())
	cmd.AddCommand(initSuperAdminCommand())

	verflag.AddFlags(cmd.PersistentFlags())

	log.Debugw("NewCommand return")
	return cmd
}

func run() error {
	/*
		// performance graph
		f, perr := os.Create("cpu.pprof")
		if perr != nil {
			log.Errorw("", "error", perr)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		// go tool pprof -http=":8888" api-gateway ./cpu.pprof
	*/
	limitCPU()
	// print non-sensitive config
	cfg := config.Global()
	log.Infow("server config",
		"addr", cfg.ServerOptions.Addr,
		"port", cfg.ServerOptions.Port,
		"runmode", cfg.ServerOptions.Runmode,
		"healthCheckPath", cfg.ServerOptions.HealthCheckPath,
		"sites_count", len(cfg.Sites),
		"caches_count", len(cfg.Caches),
		"rateLimiters_count", len(cfg.RateLimiters),
	)

	// do init
	InitRedis(context.Background(), config.Global().Db.Redis)
	InitCaches(context.Background(), config.Global().Caches)
	InitRateLimiterConfigs(config.Global().RateLimiters)

	// init user module if configured
	var userMod *user.Module
	if cfg.User != nil {
		var err error
		userMod, err = user.New(context.Background(), *cfg.User)
		if err != nil {
			log.Fatalw("User module initialization failed", "error", err)
			return err
		}
	}

	// init auth module if user module is available and any site uses gateway auth
	var authMod *auth.Module
	if userMod != nil {
		authCfg := buildAuthConfig(cfg)
		if len(authCfg.Providers) > 0 {
			authMod = auth.New(authCfg, userMod)
		}
	}

	// init RBAC if enabled
	var rbacInstance *rbac.RBAC
	if cfg.RBAC != nil && cfg.RBAC.Enabled {
		if userMod == nil {
			log.Fatalw("RBAC requires user module to be configured")
			return fmt.Errorf("rbac enabled but user module not configured")
		}
		dsn := cfg.User.DB.DSN
		schema := rbac.SchemaFromDSN(dsn)
		var err error
		rbacInstance, err = rbac.New(context.Background(), *cfg.RBAC, dsn, schema, userMod.DB(), userMod)
		if err != nil {
			log.Fatalw("RBAC initialization failed", "error", err)
			return err
		}
	}

	// init mux
	options := config.Global().ServerOptions
	addr := options.Addr + ":" + options.Port
	r := mux.NewRouter()

	routeInitErr := initRoutes(config.Global(), r, rbacInstance, authMod)
	if routeInitErr != nil {
		return routeInitErr
	}

	// mount user admin API
	if userMod != nil {
		adminPath := "/admin"
		if cfg.RBAC != nil && cfg.RBAC.AdminPath != "" {
			adminPath = cfg.RBAC.AdminPath
		}
		r.PathPrefix(adminPath + "/").Handler(
			http.StripPrefix(adminPath, mergeAdminHandlers(userMod, rbacInstance)),
		)
		log.Infow("Admin API mounted", "path", adminPath)
	} else if rbacInstance != nil && cfg.RBAC != nil {
		adminPath := cfg.RBAC.AdminPath
		if adminPath == "" {
			adminPath = "/admin"
		}
		r.PathPrefix(adminPath + "/").Handler(
			http.StripPrefix(adminPath, rbacInstance.AdminHandler()),
		)
		log.Infow("RBAC admin API mounted", "path", adminPath)
	}

	httpsrv := &http.Server{
		Handler: r,
		Addr:    addr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	if common.FLAG_DEBUG {
		httpsrv.WriteTimeout = 300 * time.Second
		httpsrv.ReadTimeout = 300 * time.Second
	}

	go func() {
		if options.Tls != nil {
			log.Infow("Start to listening the incoming requests on https address", "addr", addr)
			if err := httpsrv.ListenAndServeTLS(options.Tls.CertPath, options.Tls.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalw(err.Error())
			}
		} else {
			log.Infow("Start to listening the incoming requests on http address", "addr", addr)
			if err := httpsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalw(err.Error())
			}
		}
	}()

	// https://pkg.go.dev/os/signal#Notify
	// https://stackoverflow.com/questions/68593779/can-unbuffered-channel-be-used-to-receive-signal
	//  the sender is non-blocking. So if the receiver is not waiting for a signal, the message will be discarded.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Infow("Shutting down server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	log.Infow("Shutting down server ... in 30 seconds")
	defer cancel()

	if err := httpsrv.Shutdown(ctx); err != nil {
		log.Errorw("Insecure Server forced to shutdown", "err", err)
		return err
	}
	log.Infow("Server exiting")
	return nil
}

func limitCPU() {
	if limitCpu > 0 {
		runtime.GOMAXPROCS(limitCpu)
	}
	log.Infow(fmt.Sprintf("using cpu: %d", runtime.GOMAXPROCS(-1)))
}

func buildAuthConfig(cfg *config.Config) auth.Config {
	providerSet := make(map[string]bool)
	for _, site := range cfg.Sites {
		if site.Auth != nil && site.Auth.Mode == "gateway" {
			for _, p := range site.Auth.Providers {
				providerSet[p.Type] = true
			}
		}
	}
	var providers []auth.ProviderConfig
	for t := range providerSet {
		providers = append(providers, auth.ProviderConfig{Type: t})
	}
	return auth.Config{Providers: providers}
}

func mergeAdminHandlers(userMod *user.Module, rbacInstance *rbac.RBAC) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", userMod.AdminHandler())
	if rbacInstance != nil {
		mux.Handle("/tenants/{tenantId}/roles", rbacInstance.AdminHandler())
		mux.Handle("/tenants/{tenantId}/roles/", rbacInstance.AdminHandler())
		mux.Handle("/tenants/{tenantId}/users/{userId}/roles", rbacInstance.AdminHandler())
		mux.Handle("/tenants/{tenantId}/permissions", rbacInstance.AdminHandler())
		mux.Handle("/tenants/{tenantId}/permissions/", rbacInstance.AdminHandler())
	}
	return mux
}
