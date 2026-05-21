package main

import (
	"fmt"
	"log"

	"dast-fuzzer/internal/payload" // 본인의 모듈명으로 변경하세요
)

func main() {
	// 1. 파일에서 페이로드 로드
	payloads, err := payload.LoadPayloads("payloads/sqli.txt")
	if err != nil {
		log.Fatalf("페이로드 로드 실패: %v", err)
	}

	fmt.Printf("총 %d개의 페이로드를 불러왔습니다.\n\n", len(payloads))

	targetURL := "http://example.com/api/users?id=123"
	targetParam := "id"

	// 2. URL에 각각 주입해보기
	fmt.Printf("타겟 URL: %s\n", targetURL)
	fmt.Printf("타겟 파라미터: %s\n", targetParam)
	fmt.Println("--------------------------------------------------")

	for i, p := range payloads {
		injectedURL, err := payload.InjectQueryParam(targetURL, targetParam, p)
		if err != nil {
			fmt.Println("URL 주입 에러:", err)
			continue
		}
		fmt.Printf("[Payload %d] %s\n", i+1, injectedURL)
	}
}
