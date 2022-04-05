// Package gumroad provides license checking using gumroad.
package gumroad

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Check a key against a product permalink in gumroad.
func Check(product, key string) error {
	return doCheck("https://api.gumroad.com/v2/licenses/verify", product, key)
}

// Capture the root certificate pool at build time. `x509.SystemCertPool` is guaranteed not to return
// an error when GOOS is darwin or windows. When GOOS is unix or plan9, `x509.SystemCertPool` will
// only return an error if it was unable to find or parse any system certificates.
var certPool, _ = x509.SystemCertPool()

// construct a package-level http.RoundTripper to use instead of http.DefaultTransport
var transport = &http.Transport{
	// don't use the runtime system's cert pool, since it may include a certificate
	// that this package does not want to trust
	TLSClientConfig: &tls.Config{RootCAs: certPool},

	// since TLSClientConfig above is not nil, HTTP/2 needs to be explicitly enabled
	ForceAttemptHTTP2: true,

	// copy the other non-zero-value attributes from http.DefaultTransport
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	Proxy:                 http.ProxyFromEnvironment,
}

// construct a package-local client to use instead of http.DefaultClient
var client = &http.Client{
	// 5 seconds should be plenty for GumRoad to respond
	Timeout:   5 * time.Second,
	Transport: transport,
}

func doCheck(api, product, key string) error {
	resp, err := client.PostForm(api,
		url.Values{
			"product_permalink": {product},
			"license_key":       {key},
		})
	if err != nil {
		return fmt.Errorf("license: failed check license: %w", err)
	}

	bts, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("license: failed check license: %w", err)
	}
	defer resp.Body.Close()

	var gumroad GumroadResponse
	if err := json.Unmarshal(bts, &gumroad); err != nil {
		return fmt.Errorf("license: failed check license: %w", err)
	}

	if !gumroad.Success {
		return fmt.Errorf("license: invalid license: %s", gumroad.Message)
	}

	if gumroad.Purchase.Refunded {
		return fmt.Errorf("license: license was refunded and is now invalid")
	}

	if !gumroad.Purchase.SubscriptionCancelledAt.IsZero() {
		return fmt.Errorf("license: subscription was canceled, license is now invalid")
	}

	if !gumroad.Purchase.SubscriptionFailedAt.IsZero() {
		return fmt.Errorf("license: failed to renew subscription, please check at https://gumroad.com/subscriptions/%s/manage", gumroad.Purchase.SubscriptionID)
	}

	return nil
}

type GumroadResponse struct {
	Success  bool     `json:"success"`
	Uses     int      `json:"uses"`
	Purchase Purchase `json:"purchase"`
	Message  string   `json:"message"`
}

type Purchase struct {
	Email                   string    `json:"email"`
	Refunded                bool      `json:"refunded"`
	SaleTimestamp           time.Time `json:"sale_timestamp"`
	SubscriptionCancelledAt time.Time `json:"subscription_cancelled_at"`
	SubscriptionFailedAt    time.Time `json:"subscription_failea_dat"`
	SubscriptionID          string    `json:"subscription_id"`
}
