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

// Product represents a product in Gumroad on which license keys can be verified.
type Product struct {
	API       string
	ProductID string
	Client    *http.Client
	Validate  func(GumroadResponse) error
}

// NewProduct returns a new GumroadProduct with reasonable defaults.
func NewProduct(productID string) (Product, error) {
	// early return if product permalink is empty
	if productID == "" {
		return Product{}, errors.New("license: product ID cannot be empty")
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

	return Product{
		API:       "https://api.gumroad.com/v2/licenses/verify",
		ProductID: productID,
		Client: &http.Client{
			Timeout:   time.Minute,
			Transport: transport,
		},
	}, nil
}

const maxRetries = 5

// Verify returns the result of VerifyWithContext with the background context.
func (gp Product) Verify(ctx context.Context, key string) error {
	return gp.doVerify(ctx, key, 1)
}

func (gp Product) doVerify(ctx context.Context, key string, try int) error {
	// early return if license key is empty
	if key == "" {
		return errors.New("license: license key cannot be empty")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", gp.API, strings.NewReader(url.Values{
		"product_id":  {gp.ProductID},
		"license_key": {key},
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

	// something on server side, should probably retry...
	if resp.StatusCode >= 500 {
		if try == maxRetries {
			return fmt.Errorf("license: likely gumroad issue: %s", string(bts))
		}
		time.Sleep(time.Duration(try*500) * time.Millisecond)
		return gp.doVerify(ctx, key, try+1)
	}

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

	if gumroad.Purchase.ProductID != gp.ProductID {
		return fmt.Errorf("license: invalid product ID")
	}

	if gumroad.Purchase.LicenseKey != key {
		return fmt.Errorf("license: invalid license")
	}

	if gp.Validate != nil {
		return gp.Validate(gumroad)
	}
	return nil
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
	SellerID                string    `json:"seller_id"`
	ProductID               string    `json:"product_id"`
	ProductName             string    `json:"product_name"`
	Permalink               string    `json:"permalink"`
	ProductPermalink        string    `json:"product_permalink"`
	ShortProductID          string    `json:"short_product_id"`
	Email                   string    `json:"email"`
	Price                   int       `json:"price"`
	GumroadFee              int       `json:"gumroad_fee"`
	Currency                string    `json:"currency"`
	Quantity                int       `json:"quantity"`
	DiscoverFeeCharged      bool      `json:"discover_fee_charged"`
	CanContact              bool      `json:"can_contact"`
	Referrer                string    `json:"referrer"`
	Card                    Card      `json:"card"`
	OrderNumber             int       `json:"order_number"`
	SaleID                  string    `json:"sale_id"`
	SaleTimestamp           time.Time `json:"sale_timestamp"`
	SubscriptionID          string    `json:"subscription_id"`
	Variants                string    `json:"variants"`
	OfferCode               OfferCode `json:"offer_code"`
	LicenseKey              string    `json:"license_key"`
	IsMultiseatLicense      bool      `json:"is_multiseat_license"`
	IPCountry               string    `json:"ip_country"`
	Recurrence              string    `json:"recurrence"`
	IsGiftReceiverPurchase  bool      `json:"is_gift_receiver_purchase"`
	Refunded                bool      `json:"refunded"`
	Disputed                bool      `json:"disputed"`
	DisputeWon              bool      `json:"dispute_won"`
	ID                      string    `json:"id"`
	CreatedAt               string    `json:"created_at"`
	CustomFields            []any     `json:"custom_fields"`
	SubscriptionEndedAt     time.Time `json:"subscription_ended_at"`
	SubscriptionCancelledAt time.Time `json:"subscription_cancelled_at"`
	SubscriptionFailedAt    time.Time `json:"subscription_failed_at"`
}

type Card struct {
	Visual      string `json:"visual"`
	Type        string `json:"type"`
	Bin         string `json:"bin"`
	ExpiryMonth string `json:"expiry_month"`
	ExpiryYear  string `json:"expiry_year"`
}

type OfferCode struct {
	Code               string `json:"code"`
	DisplayedAmountOff string `json:"displayed_amount_off"`
	Name               string `json:"name"`
}
