// Package gumroad provides license checking using gumroad.
package gumroad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GumroadProduct represents a product in Gumroad on which license keys can be verified.
type GumroadProduct struct {
	API     string
	Product string
	Client  *http.Client
}

// NewGumroadProduct returns a new GumroadProduct with reasonable defaults.
func NewGumroadProduct(product string) (GumroadProduct, error) {
	// early return if product permalink is empty
	if product == "" {
		return GumroadProduct{}, errors.New("license: product permalink cannot be empty")
	}

	// Capture the root certificate pool at build time. `x509.SystemCertPool` is guaranteed not to return
	// an error when GOOS is darwin or windows. When GOOS is unix or plan9, `x509.SystemCertPool` will
	// only return an error if it was unable to find or parse any system certificates.
	certPool, _ := x509.SystemCertPool()

	// construct a package-level http.RoundTripper to use instead of http.DefaultTransport
	transport := &http.Transport{
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

	return GumroadProduct{
		API:     "https://api.gumroad.com/v2/licenses/verify",
		Product: product,
		Client: &http.Client{
			// 5 seconds should be plenty for GumRoad to respond
			Timeout:   5 * time.Second,
			Transport: transport,
		},
	}, nil
}

// CheckWithContext verifies a license key against a product in Gumroad.
func (gp GumroadProduct) VerifyWithContext(ctx context.Context, key string) error {
	// early return if license key is empty
	if key == "" {
		return errors.New("license: license key cannot be empty")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", gp.API, strings.NewReader(url.Values{
		"product_permalink": {gp.Product},
		"license_key":       {key},
	}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := gp.Client.Do(req)
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

// Verify returns the result of VerifyWithContext with the background context.
func (gp GumroadProduct) Verify(key string) error {
	return gp.VerifyWithContext(context.Background(), key)
}

// GumroadResponse is an API response.
type GumroadResponse struct {
	Success  bool     `json:"success"`
	Uses     int      `json:"uses"`
	Purchase Purchase `json:"purchase"`
	Message  string   `json:"message"`
}

// Purchase is Purchase from the GumRoad API
type Purchase struct {
	Email                   string    `json:"email"`
	Refunded                bool      `json:"refunded"`
	SaleTimestamp           time.Time `json:"sale_timestamp"`
	SubscriptionCancelledAt time.Time `json:"subscription_cancelled_at"`
	SubscriptionFailedAt    time.Time `json:"subscription_failed_at"`
	SubscriptionID          string    `json:"subscription_id"`
}
