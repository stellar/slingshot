package net

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/acme/autocert"

	"github.com/interstellar/starlight/env"
)

// DefaultTLSConfig returns a tls.Config object with system default security restrictions
func DefaultTLSConfig() *tls.Config {
	tlsConfig := new(tls.Config)
	setTLSParams(tlsConfig)
	return tlsConfig
}

func setTLSParams(tlsConfig *tls.Config) {
	// Security settings from
	// https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/

	// Avoids most of the memorably-named TLS attacks
	tlsConfig.MinVersion = tls.VersionTLS12
	// Causes servers to use Go's default ciphersuite preferences,
	// which are tuned to avoid attacks. Does nothing on clients.
	tlsConfig.PreferServerCipherSuites = true
	// Only use curves which have constant-time implementations
	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
	}

	// The standard Go ciphersuites from crypto/tls/cipher_suites.go, sans
	// 3DES as it has a 64-bit block size and is therefore vulnerable to
	// Sweet32.
	tlsConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
}

var (
	acmehost string
	mux      sync.Mutex
)

func LocalOrLets(appName string) (*tls.Config, error) {
	cert, key, err := findCertKey()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if cert != "" {
		kp, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, errors.New("unable to parse cert or key")
		}
		return &tls.Config{Certificates: []tls.Certificate{kp}}, nil
	} else {
		return letsEncrypt(appName)
	}
}

func letsEncrypt(appName string) (*tls.Config, error) {
	tlsConfig := (&autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(appName, "autocert")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autoHostWhitelist,
	}).TLSConfig()
	setTLSParams(tlsConfig)

	return tlsConfig, nil
}

func findCertKey() (cert, key string, err error) {
	dir := env.String("I10R", ".") + "/certs"
	cert = filepath.Join(dir, "localhost.pem")
	key = filepath.Join(dir, "localhost-key.pem")
	_, err = os.Stat(cert)
	if err != nil {
		return "", "", err
	}
	fi, err := os.Stat(key)
	if err != nil {
		return "", "", err
	}
	if fi.Mode()&077 != 0 {
		return "", "", errors.New(key + " must be accessible only to current user")
	}
	return cert, key, nil
}

// autoHostWhitelist provides a TOFU-like mechanism as an
// autocert host policy. It whitelists the first-requested
// name and rejects all subsequent names.
// TODO: write the host name to a file in dir
func autoHostWhitelist(ctx context.Context, host string) error {
	mux.Lock()
	defer mux.Unlock()

	if acmehost == "" {
		fmt.Printf("adding %s to acmehost\n", host)
		acmehost = host
	}
	if acmehost == host {
		return nil
	}
	return errors.New("host name mismatch")
}
