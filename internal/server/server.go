package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

type Server struct {
	http.Server
}

func NewServer() *http.Server {
	// Initial load
	if err := loadCertificate(); err != nil {
		log.Fatal(err)
	}

	// Load CA for client verification
	caCert, _ := ioutil.ReadFile("ca.crt")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS13,
	}

	s := &Server{}
	mux := s.RegisterRoutes()

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Certificate reload endpoint (simulate rotation)
	go func() {
		addr := 8080
		log.Printf("Server listening on port: %d", addr)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", addr),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := loadCertificate()
				if err != nil {
					w.Write([]byte("Reload failed"))
					return
				}
				w.Write([]byte("Reloaded"))
			})); err != nil {
			log.Printf("reload endpoint error: %v", err)
		}
	}()

	return server
}

var (
	certMutex sync.RWMutex
	cert      *tls.Certificate
)

func loadCertificate() error {
	newCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return err
	}

	certMutex.Lock()
	cert = &newCert
	certMutex.Unlock()

	log.Println("Server certificate reloaded")
	return nil
}

func getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certMutex.RLock()
	defer certMutex.RUnlock()
	return cert, nil
}
