package gumroad

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIntegrationInvalidLicense(t *testing.T) {
	expected := "license: invalid license: That license does not exist for the provided product."
	err := Check("this-does-not-exist-probably", "nope")
	if err == nil || err.Error() != expected {
		t.Errorf("expected an error %q, got %v", expected, err)
	}
}

func TestErrors(t *testing.T) {
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
					t.Fatalf("expacted no error, got %v", err)
				}
			} else {
				if err == nil || err.Error() != tt.eeer {
					t.Fatalf("expected %q, got %v", tt.eeer, err)
				}
			}
		})
	}
}
