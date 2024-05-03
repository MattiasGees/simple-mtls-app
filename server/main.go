package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
)

func printHeader(r *http.Request) {
	log.Print(">>>>>>>>>>>>>>>> Header <<<<<<<<<<<<<<<<")
	// Loop over header names
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Printf("%v:%v", name, value)
		}
	}
}

func printConnState(state *tls.ConnectionState) {
	log.Print(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<<")

	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)

	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
		log.Printf("   URI SAN: %s", cert.URIs)
		humanReadableTime := cert.NotAfter.Format("Monday, January 2, 2006 15:04:05 MST")
		log.Printf("   Validity: %s", humanReadableTime)
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	printHeader(r)
	if r.TLS != nil {
		printConnState(r.TLS)
	}
	log.Print(">>>>>>>>>>>>>>>>> End <<<<<<<<<<<<<<<<<<")
	fmt.Println("")
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {
	tlsKey := flag.String("k", "/certs/tls.key", "Private key of server")
	tlsCert := flag.String("p", "/certs/tls.crt", "Public Key of Server")
	tlsCA := flag.String("c", "/certs/ca.crt", "CA Certificate")

	flag.Parse()

	// Create a channel for certificate update events
	updateCert := make(chan bool)

	// Start watching for certificate changes
	go watchForCertificateChanges(*tlsCert, *tlsKey, updateCert)

	// Start the initial server
	server := startServer(*tlsCert, *tlsKey, *tlsCA, updateCert)

	go func() {
		log.Print("(HTTPS) Listen on :8443\n")
		err := server.ListenAndServeTLS(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("(HTTPS) error listening to port: %v", err)
		}
	}()

	log.Println("Server started on port 8443...")

	// Keep the main goroutine running
	select {}
}

func startServer(certFile, keyFile, caFile string, updateCert <-chan bool) *http.Server {
	// load CA certificate file and add it to list of client CAs
	caCertFile, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("error reading CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertFile)
	result := &keypairReloader{
		certPath: certFile,
		keyPath:  keyFile,
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf(err.Error())
	}
	result.cert = &cert
	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:                caCertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		GetCertificate:           result.GetCertificateFunc(),
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Set up a /hello resource handler
	handler := http.NewServeMux()
	handler.HandleFunc("/hello", helloHandler)

	server := &http.Server{
		Addr:      ":8443",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	go func() {
		for {
			select {
			case <-updateCert:
				log.Println("Reloading certificate...")
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					log.Println("Error loading certificate:", err)
					continue
				}
				result.cert = &cert
				if err := result.maybeReload(); err != nil {
					log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
				}
				log.Println("Certificate reloaded successfully.")
			}
		}
	}()

	return server
}

func watchForCertificateChanges(certFile, keyFile string, updateCert chan<- bool) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("Error creating watcher:", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(certFile)
	if err != nil {
		log.Println("Error adding certificate file to watcher:", err)
		return
	}

	err = watcher.Add(keyFile)
	if err != nil {
		log.Println("Error adding key file to watcher:", err)
		return
	}

	for {
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Println("Ca, Certificate or key file modified. Reloading...")
			updateCert <- true
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error watching for file changes:", err)
		}
	}
}

type keypairReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}
