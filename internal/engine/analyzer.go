package engine

import (
	"strings"
)

type Vulnerability struct {
	Type        string
	Payload     string
	InjectedURL string
	Evidence    string
}

func AnalyzeResult(res FuzzResult, baselineLength int) *Vulnerability {
	if res.StatusCode == 500 {
		return &Vulnerability{
			Type:        "Error-based (Status 500)",
			Payload:     res.Payload,
			InjectedURL: res.InjectedURL,
			Evidence:    "서버가 500 Internal Server Error를 반환했습니다.",
		}
	}

	errorSignatures := []string{
		"syntax error",
		"mysql_fetch_array()",
		"ORA-01756",
		"PostgreSQL query failed",
	}

	lowerBody := strings.ToLower(res.Body)
	for _, sig := range errorSignatures {
		if strings.Contains(lowerBody, sig) {
			return &Vulnerability{
				Type:        "Error-based (DB Leak)",
				Payload:     res.Payload,
				InjectedURL: res.InjectedURL,
				Evidence:    "응답 본문에 DB 에러 시그니처가 포함되어 있습니다: " + sig,
			}
		}
	}
	if baselineLength > 0 {
		diff := res.BodyLength - baselineLength
		if diff < 0 {
			diff = -diff
		}

		if float64(diff) > float64(baselineLength)*0.3 {
			return &Vulnerability{
				Type:        "Boolean-based (Length Anomaly)",
				Payload:     res.Payload,
				InjectedURL: res.InjectedURL,
				Evidence:    "정상 응답 대비 데이터 길이 변화가 큽니다. (데이터 유출 또는 로직 우회 의심)",
			}
		}
	}

	return nil
}
