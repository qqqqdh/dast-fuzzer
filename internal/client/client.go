package client

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// FuzzClient는 최적화된 HTTP 클라이언트와 Rate Limiter를 래핑한 구조체입니다.
type FuzzClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

// NewFuzzClient는 설정값에 따라 튜닝된 FuzzClient를 반환합니다.
func NewFuzzClient(tps int, timeout time.Duration) *FuzzClient {
	// 1. http.Transport 튜닝 (소켓 고갈 방지)
	transport := &http.Transport{
		MaxIdleConns:        1000, // 전체 최대 유휴 커넥션
		MaxIdleConnsPerHost: 500,  // 단일 호스트당 최대 유휴 커넥션 (Fuzzer에 필수)
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false, // Keep-Alive 활성화
	}

	// 2. HTTP 클라이언트 생성 (타임아웃 설정)
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout, // 고루틴 릭(Leak) 방지를 위한 전역 타임아웃
	}

	// 3. Rate Limiter 설정 (초당 tps만큼의 토큰 생성, 버킷 크기는 tps와 동일하게)
	limiter := rate.NewLimiter(rate.Limit(tps), tps)

	return &FuzzClient{
		client:  client,
		limiter: limiter,
	}
}

// DoRequest는 Rate Limit과 Context 타임아웃을 준수하며 요청을 보냅니다.
func (fc *FuzzClient) DoRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	// 요청을 보내기 전, 토큰을 얻을 때까지 대기 (TPS 조절)
	err := fc.limiter.Wait(ctx)
	if err != nil {
		return nil, err
	}

	// 실제 HTTP 요청 수행
	return fc.client.Do(req.WithContext(ctx))
}
