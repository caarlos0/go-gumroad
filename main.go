// Package gumroad provides license checking using gumroad.
package gumroad

import (
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

func doCheck(api, product, key string) error {
	resp, err := http.PostForm(api,
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
