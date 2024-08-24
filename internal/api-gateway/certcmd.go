package gateway

import (
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func caCertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "cert",
		Short:        "create ca cert by rsa config",
		Long:         `create ca cert by rsa config`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := &config.Config{}
			err := cfg.ReadConfig(cfgFile)
			if err != nil {
				log.Errorw("start failed", "error", err)
				return err
			}
			config.Set(cfg)

			runCertCmd()
			return nil
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

	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "The path to the blog configuration file. Empty string for no configuration file.")
	return cmd
}

func runCertCmd() {
	// Generate a new RSA private key
	sites := config.Global().Sites
	for _, site := range sites {
		jwtCfg := site.JWTConfig
		if jwtCfg == nil || jwtCfg.RSAPrivateKey == "" {
			log.Infow(fmt.Sprintf("no private key site: %s", site.HostName))
			continue
		}
		privKey, err := jwt.InitRSAPrivateKey(jwtCfg.RSAPrivateKey)
		if err != nil {
			log.Errorw(fmt.Sprintf("init private key site: %s", site.HostName), "error", err)
		}
		generateCert(privKey, site.HostName)
	}
}

func generateCert(privKey *rsa.PrivateKey, host string) {
	// Generate a CA certificate template
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			CommonName:   "Local CA",
			Organization: []string{"Local Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
	if err != nil {
		panic(err)
	}

	// Write the CA certificate to a file
	certOut, err := os.Create(fmt.Sprintf("%s.crt", host))
	if err != nil {
		panic(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// Write the RSA private key to a file
	keyOut, err := os.Create(fmt.Sprintf("%s.key", host))
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	keyOut.Close()
}
