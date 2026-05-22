package report

import (
	"encoding/json"
	"os"
	"time"

	"dast-fuzzer/internal/engine"
)

// ScanReport는 최종 리포트의 메타데이터와 취약점 목록을 담는 최상위 구조체입니다.
type ScanReport struct {
	ScanTime        time.Time              `json:"scan_time"`
	TotalVulns      int                    `json:"total_vulnerabilities"`
	Vulnerabilities []engine.Vulnerability `json:"vulnerabilities"`
}

// GenerateJSONReport는 수집된 취약점 배열을 받아 예쁜 포맷의 JSON 파일로 저장합니다.
func GenerateJSONReport(vulns []engine.Vulnerability, filepath string) error {
	// 1. 리포트 구조체 초기화
	report := ScanReport{
		ScanTime:        time.Now(),
		TotalVulns:      len(vulns),
		Vulnerabilities: vulns,
	}

	// 2. 구조체를 JSON 문자열로 변환 (MarshalIndent를 쓰면 줄바꿈과 들여쓰기가 적용되어 사람이 읽기 편해집니다)
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// 3. 파일로 저장 (파일 권한 0644: 소유자 읽기/쓰기, 그 외 읽기)
	err = os.WriteFile(filepath, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}
