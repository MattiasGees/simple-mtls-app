package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

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
	server := flag.String("s", "https://localhost:8443/hello", "HTTP Address for Server")
	uriMatch := flag.String("u", "spiffe://cert-manager-spiffe.mattiasgees.be/ns/mtls-app/sa/server", "SPIFFE ID to match")

	flag.Parse()

	for {
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
		serverID := spiffeid.RequireFromString(*uriMatch)

		// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate has SPIFFE ID.
		tlsConfig := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeID(serverID))
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		// Request /hello over port 8443 via the GET method
		// Using curl the verify it :
		// curl --trace trace.log -k \
		//   --cacert ./ca.crt  --cert ./client.b.crt --key ./client.b.key  \
		//     https://localhost:8443/hello

		r, err := client.Get(*server)
		if err != nil {
			log.Fatalf("error making get request: %v", err)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("error reading response: %v", err)
		}

		// Print the response body, header and state to stdout
		log.Print(">>>>>>>>>>>>>>>> Body <<<<<<<<<<<<<<<<")
		log.Printf("%s\n", body)
		printHeader(r)
		if r.TLS != nil {
			printConnState(r.TLS)
		}
		log.Print(">>>>>>>>>>>>>>>>> End <<<<<<<<<<<<<<<<<<")
		fmt.Println("")
		r.Body.Close()
		time.Sleep(15 * time.Second)
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

func printHeader(r *http.Response) {
	log.Print(">>>>>>>>>>>>>>>> Header <<<<<<<<<<<<<<<<")
	// Loop over header names
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Printf("%v:%v", name, value)
		}
	}
}
