// Copyright (C) 2024 Michael J. Fromberger. All Rights Reserved.

package tlsutil_test

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/tlsutil"
)

func TestCertPlumbing(t *testing.T) {
	// Create a signing certificate, and use it to sign a server certificate.
	ca, err := tlsutil.NewSigningCert(1*time.Hour, &x509.Certificate{
		Subject: pkix.Name{Organization: []string{t.Name()}},
		Issuer:  pkix.Name{Organization: []string{"tlsutil test package"}, CommonName: "Testy McTestface"},
	})
	if err != nil {
		t.Fatalf("Create signing cert: %v", err)
	}
	t.Logf("Signing cert:\n%s", ca.CertPEM())

	// Start an HTTP server using the server certificate.
	const testResponse = "Thank you for your input"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testResponse)
	})

	// Create a cert pool containing the signing cert, and a client using that
	// pool to validate certs.
	//
	// Note that the httptest.Server will give us a client already wired up to
	// accept its baked-in test cert, but here we want to exercise the cert that
	// we installed.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertPEM())
	awareClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	defer awareClient.CloseIdleConnections()

	startServer := func(t *testing.T, serverCert tls.Certificate) *httptest.Server {
		hs := httptest.NewUnstartedServer(handler)
		hs.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
		hs.StartTLS()
		t.Cleanup(hs.Close)
		return hs
	}

	t.Run("Valid", func(t *testing.T) {
		// Create a valid server cert and wire it up to an HTTP server.
		sc, err := tlsutil.NewServerCert(1*time.Hour, ca, &x509.Certificate{
			Subject:     pkix.Name{Organization: []string{"HTTP test service"}},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		})
		if err != nil {
			t.Fatalf("Create server cert: %v", err)
		}
		t.Logf("Server cert:\n%s", sc.CertPEM())

		serverCert, err := sc.TLSCertificate()
		if err != nil {
			t.Fatalf("Get TLS cert: %v", err)
		}

		hs := startServer(t, serverCert)

		// A call without the signing cert in the CA pool should fail TLS validation.
		t.Run("NoCA", func(t *testing.T) {
			rsp, err := http.Get(hs.URL)
			if err == nil {
				t.Errorf("Get %q: got %v, want error", hs.URL, rsp)
			} else if !strings.Contains(err.Error(), "failed to verify") {
				t.Errorf("Got %q, want trust error", err)
			}
		})

		t.Run("YesCA", func(t *testing.T) {
			rsp, err := awareClient.Get(hs.URL)
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}
			body, err := io.ReadAll(rsp.Body)
			rsp.Body.Close()
			if err != nil {
				t.Errorf("Read response body: %v", err)
			}
			if got, want := rsp.StatusCode, http.StatusOK; got != want {
				t.Errorf("Status is %d, want %d", got, want)
			}
			if got := string(body); got != testResponse {
				t.Errorf("Response is %q, want %q", got, testResponse)
			}
		})
	})

	t.Run("Expired", func(t *testing.T) {
		// Create an expired server cert and make sure the client notices.
		sc, err := tlsutil.NewServerCert(1*time.Hour, ca, &x509.Certificate{
			Subject:     pkix.Name{Organization: []string{"HTTP test service"}},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
			NotBefore:   time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // "a long time ago"
		})
		if err != nil {
			t.Fatalf("Create server cert: %v", err)
		}
		t.Logf("Server cert:\n%s", sc.CertPEM())

		serverCert, err := sc.TLSCertificate()
		if err != nil {
			t.Fatalf("Get TLS cert: %v", err)
		}

		hs := startServer(t, serverCert)

		rsp, err := awareClient.Get(hs.URL)
		if err == nil {
			t.Errorf("Get %q: got %v, wanted error", hs.URL, rsp)
		} else if !strings.Contains(err.Error(), "certificate has expired") {
			t.Errorf("Got %q, want expiration error", err)
		}
	})
}

func TestLoadCertificate(t *testing.T) {
	c, err := tlsutil.NewSigningCert(time.Minute, &x509.Certificate{})
	if err != nil {
		t.Fatalf("Create cert 1: %v", err)
	}
	s, err := tlsutil.NewServerCert(time.Minute, c, &x509.Certificate{})
	if err != nil {
		t.Fatalf("Create cert 2: %v", err)
	}

	check := func(t *testing.T, srcs ...[]byte) {
		t.Helper()
		if _, err := tlsutil.LoadCertificate(srcs...); err != nil {
			t.Errorf("Load: unexpected error: %v", err)
		}
	}
	checkFail := func(t *testing.T, srcs [][]byte, want ...string) {
		t.Helper()
		got, err := tlsutil.LoadCertificate(srcs...)
		if err == nil {
			t.Fatalf("Load: got %+v, want error", got)
		}
		gotErr := err.Error()
		for _, w := range want {
			if !strings.Contains(gotErr, w) {
				t.Errorf("Error is missing %q", w)
			}
		}
		if t.Failed() {
			t.Logf("Error string is: %q", gotErr)
		}
	}

	t.Run("Empty", func(t *testing.T) {
		checkFail(t, [][]byte{}, "missing certificate", "missing private key")
	})

	t.Run("Partial", func(t *testing.T) {
		checkFail(t, [][]byte{s.CertPEM()}, "missing private key")
		checkFail(t, [][]byte{s.PrivKeyPEM()}, "missing certificate")
	})

	t.Run("OK", func(t *testing.T) {
		check(t, c.CertPEM(), c.PrivKeyPEM())
		check(t, c.PrivKeyPEM(), c.CertPEM())
	})

	t.Run("Double", func(t *testing.T) {
		checkFail(t, [][]byte{s.CertPEM(), s.PrivKeyPEM(), s.CertPEM()}, "multiple certificates")
		checkFail(t, [][]byte{s.CertPEM(), s.PrivKeyPEM(), c.PrivKeyPEM()}, "multiple private keys")
		batch := append(s.CertPEM(), c.CertPEM()...)
		checkFail(t, [][]byte{batch}, "multiple certificates") // in a single batch
	})

	t.Run("BadCert", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("ho ho ho"),
		})
		checkFail(t, [][]byte{bad}, "invalid certificate")
	})

	t.Run("BadKey", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("where is ur god now"),
		})
		checkFail(t, [][]byte{bad}, "invalid private key")
	})

	t.Run("WrongKey", func(t *testing.T) {
		key, err := rsa.GenerateKey(crand.Reader, 1024)
		if err != nil {
			t.Fatalf("Generate RSA key: %v", err)
		}
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("Marshal RSA key: %v", err)
		}
		bad := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: data,
		})
		checkFail(t, [][]byte{bad}, "unsupported key format")
	})

	t.Run("OK/Other", func(t *testing.T) {
		misc := pem.EncodeToMemory(&pem.Block{
			Type:  "GETTYSBURG ADDRESS",
			Bytes: []byte("four score and seven years ago, our fathers brought forth on this continent..."),
		})
		check(t, misc, c.CertPEM(), misc, c.PrivKeyPEM(), misc, misc)
	})
}
