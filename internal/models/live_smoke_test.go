package models

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveFetchSmoke(t *testing.T) {
	if os.Getenv("MODEL_LIVE") != "1" {
		t.Skip("set MODEL_LIVE=1 to run the live catalog fetch")
	}
	if testing.Short() {
		t.Skip("skip live fetch in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := Fetch(ctx, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Logf("fetched %d/%d models; skipped: %v", len(res.Models), res.Total, res.Skipped)
	for id, info := range res.Models {
		if info.FunctionID == "" || info.Slug == "" || info.Namespace == "" {
			t.Errorf("%s incomplete: %+v", id, info)
		}
	}
}
