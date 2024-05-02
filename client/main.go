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
	"time"
)

func main() {

	tlsKey := flag.String("k", "/certs/tls.key", "Private key of server")
	tlsCert := flag.String("p", "/certs/tls.crt", "Public Key of Server")
	tlsCA := flag.String("c", "/certs/ca.crt", "CA Certificate")
	server := flag.String("s", "https://localhost:8443/hello", "HTTP Address for Server")

	flag.Parse()

	cert, err := os.ReadFile(*tlsCA)
	if err != nil {
		log.Fatalf("could not open certificate file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert)

	log.Println("Load key pairs - ", tlsCert, tlsKey)
	certificate, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
	}

	client := http.Client{
		Timeout: time.Minute * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:               caCertPool,
				Certificates:          []tls.Certificate{certificate},
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: verifyPeerCertificate,
			},
		},
	}

	// Request /hello over port 8443 via the GET method
	// Using curl the verfiy it :
	// curl --trace trace.log -k \
	//   --cacert ./ca.crt  --cert ./client.b.crt --key ./client.b.key  \
	//     https://localhost:8443/hello

	r, err := client.Get(*server)
	if err != nil {
		log.Fatalf("error making get request: %v", err)
	}

	// Read the response body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("error reading response: %v", err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)

	// Print the URI SAN of the server certificate
	for _, cert := range r.TLS.PeerCertificates {
		fmt.Println("URI SAN:", cert.URIs)
		humanReadableTime := cert.NotAfter.Format("Monday, January 2, 2006 15:04:05 MST")
		log.Printf("Validity: %s", humanReadableTime)
	}
}

func verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, rawCert := range rawCerts {
		c, _ := x509.ParseCertificate(rawCert)
		if len(c.URIs) > 0 {
			for _, uri := range c.URIs {
				log.Println(uri.String())
				if uri.String() == "spiffe://cert-manager-spiffe.mattiasgees.be/ns/mtls-app/sa/server" {
					fmt.Println("Match for URI")
					return nil // Connection verified
				}
			}
		}
	}
	return fmt.Errorf("no matching URI SAN found")
}