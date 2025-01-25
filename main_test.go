package gumroad

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

const license = "DEADBEEF-CAFE1234-5678DEAD-BEEFCAFE"

func TestIntegrationInvalidLicense(t *testing.T) {
	t.Parallel()
	expected := "license: invalid license: That license does not exist for the provided product."
	p, err := NewProduct("this-does-not-exist-probably")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	err = p.Verify(context.Background(), "nope")
	if err == nil || err.Error() != expected {
		t.Errorf("expected an error %q, got %v", expected, err)
	}
}

func TestEmptyProduct(t *testing.T) {
	t.Parallel()
	expected := "license: product ID cannot be empty"
	_, err := NewProduct("")
	if err == nil || err.Error() != expected {
		t.Fatalf("expected %q, got %v", expected, err)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	for name, val := range testCases {
		tt := val
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

			p, err := NewProduct(tt.product)
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			p.API = ts.URL
			err = p.Verify(context.Background(), tt.key)

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

func Test5xx(t *testing.T) {
	t.Parallel()

	calls := 0

	// server will stand in for GumRoad, and assume that any license it sees is invalid
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		t.Log("try", calls)
		if calls == 3 {
			bts, _ := json.Marshal(GumroadResponse{
				Success: true,
				Purchase: Purchase{
					SaleTimestamp: time.Now(),
					Email:         "foo@example.com",
					ProductID:     "product",
				},
			})
			_, _ = w.Write(bts)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`some error`))
	}))
	t.Cleanup(server.Close)

	p, err := NewProduct("product")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	p.API = server.URL
	p.Client = server.Client()

	err = p.Verify(context.Background(), license)
	if err != nil {
		t.Fatal("expected no error")
	}
	if calls != 3 {
		t.Errorf("should have called the api 3 times, but called %d", calls)
	}
}

func TestMITM(t *testing.T) {
	t.Parallel()
	const license = "DEADBEEF-CAFE1234-5678DEAD-BEEFCAFE"
	const productID = "product-id-1234"
	const sellerID = "seller-id-1234"

	// server will stand in for GumRoad, and assume that any license it sees is invalid
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		data, err := url.ParseQuery(string(body))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		resp := GumroadResponse{
			Success: data.Get("license_key") == license,
			Purchase: Purchase{
				ProductID: productID,
				SellerID:  sellerID,
			},
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

	p, err := NewProduct(productID)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	p.Validate = func(gr GumroadResponse) error {
		if gr.Purchase.SellerID != sellerID {
			return fmt.Errorf("invalid seller id")
		}
		return nil
	}
	p.API = server.URL
	// Save the default client, which does not trust the test TLS certificate
	defaultClient := p.Client
	// The server.Client() is configured to trust the test TLS certificate
	p.Client = server.Client()
	err = p.Verify(context.Background(), "fake-key")
	if !strings.Contains(err.Error(), "invalid license") {
		t.Fatalf("expected error to indicate that the license is invalid, but got: %s", err)
	}
	if err := p.Verify(context.Background(), license); err != nil {
		t.Fatalf("unexpected error when checking valid key: %s", err)
	}

	// mitm will act as a man-in-the-middle proxy, and will respond as if any license is valid
	mitm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(GumroadResponse{
			Success: true,
			Purchase: Purchase{
				ProductID: productID,
				SellerID:  sellerID,
			},
		}); err != nil {
			t.Errorf("error encoding response: %s", err)
		}
	}))
	t.Cleanup(mitm.Close)
	// Throw away the log message from http.Server.go complaining about the invalid TLS cert
	mitm.Config.ErrorLog = log.New(io.Discard, "", 0)

	p.API = mitm.URL
	// Set the client back to the default, which doesn't trust the test certificate used by mitm
	p.Client = defaultClient
	err = p.Verify(context.Background(), license)
	if err == nil {
		t.Fatalf("MITM was successful")
	} else if !strings.Contains(err.Error(), "failed check license") {
		t.Fatalf("expected error to indicate that the license check failed, but got: %s", err)
	}

	// proxyServer will act as a legitimate reverse proxy
	serverURL, _ := url.Parse(server.URL)
	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	// The proxy needs to trust the test TLS certificate
	proxy.Transport = server.Client().Transport
	proxyServer := httptest.NewTLSServer(proxy)
	t.Cleanup(proxyServer.Close)

	p.API = proxyServer.URL
	p.Client = proxyServer.Client()
	err = p.Verify(context.Background(), "fake-key")
	if !strings.Contains(err.Error(), "invalid license") {
		t.Fatalf("expected error to indicate that the license is invalid, but got: %s", err)
	}
	if err := p.Verify(context.Background(), license); err != nil {
		t.Fatalf("unexpected error when checking valid key: %s", err)
	}
}

func BenchmarkErrors(b *testing.B) {
	for name, tt := range testCases {
		b.Run(name, func(b *testing.B) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bts, err := json.Marshal(tt.resp)
				if err != nil {
					b.Fatalf("unexpected error: %v", err)
				}
				fmt.Fprintln(w, string(bts))
			}))
			b.Cleanup(ts.Close)

			for n := 0; n < b.N; n++ {
				p, _ := NewProduct("product")
				p.API = ts.URL
				_ = p.Verify(context.Background(), "key")
			}
		})
	}
}

var testCases = map[string]struct {
	product, key string
	resp         GumroadResponse
	eeer         string
}{
	"invalid license": {
		product: "product", key: "key",
		resp: GumroadResponse{
			Success: false,
			Message: "some error",
		},
		eeer: "license: invalid license: some error",
	},
	"refunded": {
		product: "product", key: "key",
		resp: GumroadResponse{
			Success: true,
			Purchase: Purchase{
				Refunded: true,
			},
		},
		eeer: "license: license was refunded and is now invalid",
	},
	"canceled": {
		product: "product", key: "key",
		resp: GumroadResponse{
			Success: true,
			Purchase: Purchase{
				SubscriptionCancelledAt: time.Now(),
			},
		},
		eeer: "license: subscription was canceled, license is now invalid",
	},
	"failed": {
		product: "product", key: "key",
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
		product: "product", key: "key",
		resp: GumroadResponse{
			Success: true,
			Purchase: Purchase{
				SaleTimestamp: time.Now(),
				Email:         "foo@example.com",
				ProductID:     "product",
			},
		},
	},
	"blank key": {
		product: "product", key: "",
		eeer: "license: license key cannot be empty",
	},
}
