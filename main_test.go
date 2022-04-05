package gumroad

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationInvalidLicense(t *testing.T) {
	t.Parallel()
	expected := "license: invalid license: That license does not exist for the provided product."
	err := Check("this-does-not-exist-probably", "nope")
	if err == nil || err.Error() != expected {
		t.Errorf("expected an error %q, got %v", expected, err)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		resp GumroadResponse
		eeer string
	}{
		"invalid license": {
			resp: GumroadResponse{
				Success: false,
				Message: "some error",
			},
			eeer: "license: invalid license: some error",
		},
		"refunded": {
			resp: GumroadResponse{
				Success: true,
				Purchase: Purchase{
					Refunded: true,
				},
			},
			eeer: "license: license was refunded and is now invalid",
		},
		"canceled": {
			resp: GumroadResponse{
				Success: true,
				Purchase: Purchase{
					SubscriptionCancelledAt: time.Now(),
				},
			},
			eeer: "license: subscription was canceled, license is now invalid",
		},
		"failed": {
			resp: GumroadResponse{
				Success: true,
				Purchase: Purchase{
					SubscriptionFailedAt: time.Now(),
					SubscriptionID:       "xyz",
				},
			},
			eeer: "license: failed to renew subscription, please check at https://gumroad.com/subscriptions/xyz/manage",
		},
		"valid": {
			resp: GumroadResponse{
				Success: true,
				Purchase: Purchase{
					SaleTimestamp: time.Now(),
					Email:         "foo@example.com",
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bts, err := json.Marshal(tt.resp)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				fmt.Fprintln(w, string(bts))
			}))
			t.Cleanup(ts.Close)

			err := doCheck(ts.URL, "product", "key")

			if tt.eeer == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			} else {
				if err == nil || err.Error() != tt.eeer {
					t.Fatalf("expected %q, got %v", tt.eeer, err)
				}
			}
		})
	}
}

//go:generate go run generate_cert.go -host 127.0.0.1,::1 -ca self -duration 87600h -rsa-bits 4096    -out testdata/ca.pem
//go:generate go run generate_cert.go -host 127.0.0.1,::1 -ca testdata/ca.pem       -ecdsa-curve P256 -out testdata/mitm.pem

func TestMITM(t *testing.T) {
	t.Parallel()
	license := "DEADBEEF-CAFE1234-5678DEAD-BEEFCAFE"

	// server will stand in for GumRoad, and assume that any license it sees is invalid
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		data, err := url.ParseQuery(string(body))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		resp := GumroadResponse{
			Success: data.Get("license_key") == license,
		}

		switch resp.Success {
		case true:
			w.WriteHeader(http.StatusOK)
		case false:
			w.WriteHeader(http.StatusNotFound)
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("error encoding response: %s", err)
		}
	}))
	t.Cleanup(server.Close)

	// add server's certificate to the trusted pool, as if it was signed by one the build system's
	// trusted CAs (which is the case for GumRoad).
	certPool.AddCert(server.Certificate())

	err := doCheck(server.URL, "product", "fake-key")
	if !strings.Contains(err.Error(), "invalid license") {
		t.Fatalf("expected error to indicate that the license is invalid, but got: %s", err)
	}

	if err := doCheck(server.URL, "product", license); err != nil {
		t.Fatalf("unexpected error when checking valid key: %s", err)
	}

	// mitm will act as a man-in-the-middle proxy, and will respond as if any license is valid
	mitm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(GumroadResponse{Success: true}); err != nil {
			t.Errorf("error encoding response: %s", err)
		}
	}))

	mitm.TLS = &tls.Config{Certificates: []tls.Certificate{parseCert(t, "mitm.pem")}}
	mitm.Config.ErrorLog = log.New(ioutil.Discard, "", 0)
	mitm.StartTLS()
	t.Cleanup(mitm.Close)

	err = doCheck(mitm.URL, "product", license)
	if !strings.Contains(err.Error(), "failed check license") {
		t.Fatalf("expected error to indicate that the license check failed, but got: %s", err)
	}

	// proxyServer will act as a legitimate reverse proxy
	serverURL, _ := url.Parse(server.URL)
	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	proxy.Transport = transport
	proxyServer := httptest.NewTLSServer(proxy)
	t.Cleanup(proxyServer.Close)

	err = doCheck(proxyServer.URL, "product", "fake-key")
	if !strings.Contains(err.Error(), "invalid license") {
		t.Fatalf("expected error to indicate that the license is invalid, but got: %s", err)
	}

	if err := doCheck(proxyServer.URL, "product", license); err != nil {
		t.Fatalf("unexpected error when checking valid key: %s", err)
	}
}

func parseCert(t *testing.T, file string) tls.Certificate {
	fp := filepath.Join("testdata", file)

	bytes, err := ioutil.ReadFile(fp)
	if err != nil {
		t.Fatalf("cannot read %s: %s", fp, err)
	}

	cert, err := tls.X509KeyPair(bytes, bytes)
	if err != nil {
		t.Fatalf("error creating tls.Certificate: %s", err)
	}

	return cert
}
