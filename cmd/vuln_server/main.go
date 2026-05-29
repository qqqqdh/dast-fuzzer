// cmd/vuln_server/main.go
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	// [추가된 부분] 메인 페이지 HTML 서빙
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "cmd/vuln_server/index.html")
	})

	// 기존 API 엔드포인트 유지
	http.HandleFunc("/api/v1/user", getUserHandler)
	http.HandleFunc("/api/v1/board", postBoardHandler)

	fmt.Println("==================================================")
	fmt.Println("⚠️  [경고] 취약점 실습용 샌드박스 서버 가동")
	fmt.Println("👉  웹 UI 접속: http://localhost:8081")
	fmt.Println("==================================================")

	http.ListenAndServe(":8081", nil)
}

// [타겟 1] GET 요청 핸들러 (Error-based & Boolean-based SQLi 취약점)
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	// 취약점 A: Error-based (싱글쿼터가 들어가면 에러 반환)
	if strings.Contains(id, "'") && !strings.Contains(strings.ToUpper(id), "OR") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error: syntax error near 'WHERE id='"))
		return
	}

	// 취약점 B: Boolean-based (참 조건이 성립하면 전체 유저 정보 유출로 인해 길이가 확 길어짐)
	if strings.Contains(strings.ReplaceAll(id, " ", ""), "1=1") || strings.Contains(strings.ToUpper(id), "OR") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":1, "name":"admin", "pw":"secret"}, {"id":2, "name":"user1", "pw":"1234"}, {"id":3, "name":"user2", "pw":"qwer"}, {"id":4, "name":"user3", "pw":"asdf"}]`))
		return
	}

	// 정상 응답 (Baseline 기준 길이)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`[{"id":1, "name":"admin"}]`))
}

// [타겟 2] POST 요청 핸들러 (JSON Body SQLi 취약점)
func postBoardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	bodyStr := string(body)

	// 취약점 C: JSON 바디에 페이로드가 주입되면 오라클 DB 에러 노출
	if strings.Contains(bodyStr, "'") || strings.Contains(bodyStr, "OR") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ORA-01756: quoted string not properly terminated"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "success", "message": "정상적으로 등록되었습니다."}`))
}
