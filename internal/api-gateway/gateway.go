package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"api-gateway/internal/store"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/verflag"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

func NewCommand() *cobra.Command {
	log.Debugw("NewCommand begin")
	cmd := &cobra.Command{
		Use:          "Go api-gateway",
		Short:        "A good Go practical project",
		Long:         `A good Go practical project, used to create user with basic information.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			config.ReadConfig(cfgFile)
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
	// cobra.OnInitialize(config.ReadConfig)

	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "The path to the blog configuration file. Empty string for no configuration file.")

	cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	verflag.AddFlags(cmd.PersistentFlags())

	log.Debugw("NewCommand return")
	return cmd
}

func readRoutes() error {
	// read conf
	if errStore := initStore(); errStore != nil {
		return errStore
	}
	routeRepo := store.S.Routes()
	count, list, err := routeRepo.List(context.TODO(), 0, 1000)
	log.Infow("All Route Count: " + fmt.Sprint(count))
	if err != nil {
		log.Errorw("Failed to list routes from storage", "err", err)
		return err
	}
	for _, item := range list {
		s, _ := json.Marshal(item)
		log.Infow(string(s))
	}
	return nil
}

func run() error {
	// print config
	settings, _ := json.Marshal(viper.AllSettings())
	log.Infow(string(settings))

	readRoutes()

	// init mux
	options := serverOptions()
	options = checkServerOptionsValid(options)
	addr := options.Addr + ":" + options.Port
	r := mux.NewRouter()
	r.HandleFunc("/", handleMux)
	r.HandleFunc("/upload", handleMuxPurchaseSave)
	r.HandleFunc("/download", handleMuxPurchaseSave)
	r.HandleFunc("/purchase/go", handleMux)
	r.HandleFunc("/purchase/see", handleMux)
	r.PathPrefix("/purchase/save").HandlerFunc(handleMuxPurchaseSave)
	r.PathPrefix("/qrcode").HandlerFunc(handleMuxPurchaseSave)
	r.PathPrefix("/purchase").HandlerFunc(handleAnyMux)

	http.Handle("/", r)
	httpsrv := &http.Server{
		Handler: r,
		Addr:    addr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Infow("Start to listening the incoming requests on http address", "addr", addr)
	go func() {
		if err := httpsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalw(err.Error())
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

func handleMux(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handle: ", r.Method, r.RequestURI)
	w.WriteHeader(http.StatusOK)
}
func handleAnyMux(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Any: ", r.Method, r.RequestURI)
	w.WriteHeader(http.StatusOK)
}
func handleMuxPurchaseSave(w http.ResponseWriter, r *http.Request) {
	fmt.Println("PurchaseSave Any: ", r.Method, r.RequestURI)
	resp, err := proxy.NewHTTPProxyDetailed()(context.TODO(), r)
	if err != nil {
		log.Errorw(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Debugw(fmt.Sprint(resp.StatusCode))

	for k := range w.Header() {
		delete(w.Header(), k)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()

	// Copy the response body to the http.ResponseWriter
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
