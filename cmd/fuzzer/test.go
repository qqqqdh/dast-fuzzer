package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"dast-fuzzer/internal/client"
	"dast-fuzzer/internal/engine"
	"dast-fuzzer/internal/payload"
)

func main() {
	payloads, err := payload.LoadPayloads("payloads/sqli.txt")
	if err != nil {
		log.Fatalf("페이로드 로드 실패: %v", err)
	}

	// [테스트용] 가짜 타겟 서버 수정 (특정 페이로드에 취약하게 만듦)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		// 취약점 시뮬레이션: payload에 싱글쿼터(')가 들어가면 서버 에러 발생
		if id != "123" && len(id) > 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Database syntax error near 'OR'"))
			return
		}

		// 정상 응답
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal User Data (Length Baseline)"))
	}))
	defer targetServer.Close()

	fc := client.NewFuzzClient(30, 5*time.Second)

	fmt.Printf("🚀 공격 대상: %s\n", targetServer.URL)
	fmt.Println("공격 시작...")

	results := engine.RunFuzzer(context.Background(), targetServer.URL, "id", payloads, 10, fc)

	// [새로 추가된 로직] 분석기(Analyzer)를 통한 결과 필터링
	fmt.Println("\n🔍 응답 결과 분석 중...")

	// 정상 요청의 길이를 34바이트(가짜 서버 정상 응답 기준)로 가정
	baselineLength := 34
	var vulns []engine.Vulnerability

	for _, res := range results {
		// Analyzer 호출
		if vuln := engine.AnalyzeResult(res, baselineLength); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	// 최종 취약점 리포팅
	fmt.Printf("\n🚨 %d 개의 취약점이 발견되었습니다!\n", len(vulns))
	fmt.Println("==================================================")
	for i, v := range vulns {
		fmt.Printf("[%d] %s\n", i+1, v.Type)
		fmt.Printf(" - 주입된 페이로드: %s\n", v.Payload)
		fmt.Printf(" - 탐지 증거: %s\n", v.Evidence)
		fmt.Println("--------------------------------------------------")
	}
}
