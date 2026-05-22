package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"dast-fuzzer/internal/client"
	"dast-fuzzer/internal/engine"
	"dast-fuzzer/internal/payload"
	"dast-fuzzer/internal/report"
)

func main() {
	// 1. CLI 플래그(Flag) 정의
	// flag.String("이름", "기본값", "설명")
	targetURL := flag.String("url", "", "타겟 URL (필수) (예: http://example.com/api)")
	targetParam := flag.String("param", "id", "페이로드를 주입할 파라미터 이름")
	payloadFile := flag.String("payloads", "payloads/sqli.txt", "페이로드 텍스트 파일 경로")
	numWorkers := flag.Int("workers", 10, "동시 실행할 워커(고루틴) 수")
	tps := flag.Int("tps", 30, "초당 최대 요청 수 (Rate Limit)")
	outFile := flag.String("out", "scan_report.json", "결과를 저장할 JSON 파일 경로")

	// 2. 입력받은 플래그 파싱
	flag.Parse()

	// 3. 필수 인자 검증
	if *targetURL == "" {
		fmt.Println("🚨 에러: 타겟 URL(-url)은 필수 입력값입니다.")
		fmt.Println("사용법:")
		flag.PrintDefaults() // 정의된 플래그들의 기본값과 설명을 자동으로 출력해 줍니다.
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("🕸️  병렬 웹 취약점 스캐너 (DAST Lite) 가동 준비 완료")
	fmt.Println("==================================================")
	fmt.Printf("[*] 타겟 URL    : %s\n", *targetURL)
	fmt.Printf("[*] 타겟 파라미터: %s\n", *targetParam)
	fmt.Printf("[*] 워커 수     : %d\n", *numWorkers)
	fmt.Printf("[*] 초당 제한   : %d TPS\n", *tps)
	fmt.Printf("[*] 리포트 파일 : %s\n", *outFile)
	fmt.Println("--------------------------------------------------")

	// 4. 페이로드 로드
	payloads, err := payload.LoadPayloads(*payloadFile)
	if err != nil {
		log.Fatalf("❌ 페이로드 로드 실패 (%s): %v", *payloadFile, err)
	}
	fmt.Printf("✔️  총 %d개의 페이로드 장전 완료.\n\n", len(payloads))

	// 5. 엔진 세팅 및 스캔 시작
	fc := client.NewFuzzClient(*tps, 5*time.Second)
	ctx := context.Background()

	startTime := time.Now()
	fmt.Println("🚀 스캔을 시작합니다...")

	// 플래그로 받은 값의 포인터(*)를 해제하여 넘겨줍니다.
	results := engine.RunFuzzer(ctx, *targetURL, *targetParam, payloads, *numWorkers, fc)

	// 6. 결과 분석 (기준 길이는 임의로 0으로 세팅하거나 응답의 평균을 구하도록 고도화할 수 있습니다)
	fmt.Println("🔍 응답 결과 분석 중...")
	var vulns []engine.Vulnerability
	for _, res := range results {
		// 실무 환경에서는 첫 번째 요청의 길이를 baselineLength로 삼는 로직을 추가하면 좋습니다.
		if vuln := engine.AnalyzeResult(res, 0); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	// 7. 결과 출력 및 JSON 저장
	fmt.Printf("\n🚨 %d 개의 취약점(에러 시그니처)이 발견되었습니다!\n", len(vulns))
	if len(vulns) > 0 {
		err = report.GenerateJSONReport(vulns, *outFile)
		if err != nil {
			log.Fatalf("❌ 리포트 생성 실패: %v\n", err)
		}
		fmt.Printf("📄 상세 스캔 리포트가 저장되었습니다: %s\n", *outFile)
	}
	fmt.Printf("⏱️  총 소요 시간: %.2f 초\n", time.Since(startTime).Seconds())
}
