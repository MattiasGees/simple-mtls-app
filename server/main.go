package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dyson/certman"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func main() {
	tlsKey := flag.String("k", "/certs/tls.key", "Private key of server")
	tlsCert := flag.String("p", "/certs/tls.crt", "Public Key of Server")
	tlsCA := flag.String("c", "/certs/ca.crt", "CA Certificate")
	trustDomain := flag.String("t", "cert-manager-spiffe.mattiasgees.be", "Trust Domain")
	uriMatch := flag.String("u", "spiffe://cert-manager-spiffe.mattiasgees.be/ns/mtls-app/sa/client", "SPIFFE ID to match")

	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	cm, err := certman.New(*tlsCert, *tlsKey)
	if err != nil {
		logger.Println(err)
	}
	cm.Logger(logger)
	if err := cm.Watch(); err != nil {
		logger.Println(err)
	}

	// Load the SVID from disk
	svid, err := x509svid.Load(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("Failed to load SVID: %v", err)
	}

	td := spiffeid.RequireTrustDomainFromString(*trustDomain)
	bundle, err := x509bundle.Load(td, *tlsCA)
	if err != nil {
		log.Fatalf("Failed to load bundle: %v", err)
	}

	// Allowed SPIFFE ID
	clientID := spiffeid.RequireFromString(*uriMatch)

	// Set up a `/hello` resource handler
	http.HandleFunc("/hello", helloHandler)

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate has SPIFFE ID `spiffe://example.org/client`
	tlsConfig := tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeID(clientID))
	tlsConfig.GetCertificate = cm.GetCertificate
	server := &http.Server{
		Addr:              ":8443",
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second * 10,
	}

	// Serve the SPIFFE mTLS server.
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("failed to serve: %w", err)
	}
}

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
