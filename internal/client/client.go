package client

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

type FuzzClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

func NewFuzzClient(tps int, timeout time.Duration) *FuzzClient {
	transport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	limiter := rate.NewLimiter(rate.Limit(tps), tps)

	return &FuzzClient{
		client:  client,
		limiter: limiter,
	}
}

func (fc *FuzzClient) DoRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	err := fc.limiter.Wait(ctx)
	if err != nil {
		return nil, err
	}

	return fc.client.Do(req.WithContext(ctx))
}
