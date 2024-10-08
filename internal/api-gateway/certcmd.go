package gateway

import (
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
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
				log.Fatalf("start failed: %v", err)
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
			log.Print(fmt.Sprintf("no private key site: %s", site.HostName))
			continue
		}
		privKey, err := jwt.InitRSAPrivateKey(jwtCfg.RSAPrivateKey)
		if err != nil {
			log.Fatalf("init private key site: %s: %v", site.HostName, err)
		}
		generateCert(privKey, site.HostName)
	}
}

var (
	validFrom = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor  = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA      = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
)

// src/crypto/tls/generate_cert.go
func generateCert(privKey *rsa.PrivateKey, host string) {
	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment

	var notBefore time.Time
	var err error
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			panic(err)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, host)

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privKey), privKey)
	if err != nil {
		panic(err)
	}

	certFile := fmt.Sprintf("%s.crt", host)
	certOut, err := os.Create(certFile)
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		panic(err)
	}
	if err := certOut.Close(); err != nil {
		panic(err)
	}
	fmt.Printf("wrote cert: %s\n", certFile)

	keyFile := fmt.Sprintf("%s.key", host)
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	fmt.Printf("wrote private key: %s\n", keyFile)
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
