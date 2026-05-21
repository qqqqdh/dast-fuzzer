package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"dast-fuzzer/internal/client" // 본인의 go.mod 모듈명에 맞게 수정하세요
)

func main() {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Server OK!"))
	}))
	defer targetServer.Close()

	fmt.Printf("🎯 가짜 타겟 서버가 열렸습니다: %s\n", targetServer.URL)

	// 2. FuzzClient 세팅
	tps := 50
	fc := client.NewFuzzClient(tps, 5*time.Second)
	fmt.Printf("🚀 FuzzClient 세팅 완료 (제한 속도: 초당 %d회)\n\n", tps)

	// 3. 테스트 설정
	numRequests := 200
	var wg sync.WaitGroup
	ctx := context.Background()

	fmt.Printf("총 %d개의 HTTP 요청을 동시다발적으로 발사합니다...\n", numRequests)
	startTime := time.Now()

	// 4. 똥던지기
	for i := 1; i <= numRequests; i++ {
		wg.Add(1)

		go func(reqID int) {
			defer wg.Done()

			req, _ := http.NewRequest("GET", targetServer.URL, nil)
			resp, err := fc.DoRequest(ctx, req)
			if err != nil {
				fmt.Printf("[Req %d] 실패: %v\n", reqID, err)
				return
			}
			defer resp.Body.Close()

			if reqID%50 == 0 {
				fmt.Printf("[Req %d] 성공 (상태코드: %d)\n", reqID, resp.StatusCode)
			}
		}(i)
	}

	// 모든 고루틴이 끝날 때까지 대기
	wg.Wait()
	elapsedTime := time.Since(startTime)

	// 5. 결과 검증
	fmt.Println("\n=== 테스트 결과 ===")
	fmt.Printf("소요 시간: %.2f 초\n", elapsedTime.Seconds())
	fmt.Printf("예상 소요 시간: 약 %.2f 초\n", float64(numRequests)/float64(tps))

	if elapsedTime.Seconds() >= float64(numRequests)/float64(tps) {
		fmt.Println("✅ Rate Limiter가 완벽하게 작동하여 서버를 보호했습니다!")
	} else {
		fmt.Println("❌ 요청이 너무 빨리 끝났습니다. Rate Limiter 로직을 확인하세요.")
	}
}
