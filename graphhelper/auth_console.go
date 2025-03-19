package graphhelper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// AuthResult는 인증 결과를 저장합니다.
type AuthResult struct {
	Code  string
	State string
	Error string
}

// AuthorizeWithBrowser는 브라우저를 열어 사용자 인증을 수행합니다.
func (g *GraphHelper) AuthorizeWithBrowser(userID string) error {
	// PKCE를 위한 코드 챌린지(Code Challenge)와 코드 검증자(Code Verifier) 생성
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return fmt.Errorf("코드 검증자 생성 실패: %v", err)
	}

	// 상태 토큰 생성 (CSRF 방지)
	state, err := generateRandomString(32)
	if err != nil {
		return fmt.Errorf("상태 토큰 생성 실패: %v", err)
	}

	// 인증 URL 생성
	authURL := g.GetAuthorizationURLWithPKCE(state, codeVerifier)

	// 결과를 받을 채널 생성
	resultChan := make(chan AuthResult)
	var server *http.Server

	// 로컬 웹 서버 시작
	server, err = startLocalServer(state, resultChan)
	if err != nil {
		return fmt.Errorf("로컬 서버 시작 실패: %v", err)
	}

	// 브라우저 열기
	fmt.Println("브라우저를 열어 Microsoft 계정으로 로그인합니다...")
	err = openBrowser(authURL)
	if err != nil {
		fmt.Println("브라우저를 자동으로 열 수 없습니다. 다음 URL을 브라우저에 복사하여 붙여넣으세요:")
		fmt.Println(authURL)
	}

	// 인증 결과 기다리기 (최대 5분)
	fmt.Println("브라우저에서 로그인을 완료하면 자동으로 진행됩니다...")

	select {
	case result := <-resultChan:
		// 서버 종료
		shutdownServer(server)

		if result.Error != "" {
			return fmt.Errorf("인증 오류: %s", result.Error)
		}

		// 코드를 토큰으로 교환
		return g.HandleRedirectCallbackWithPKCE(userID, result.Code, codeVerifier)

	case <-time.After(5 * time.Minute):
		// 서버 종료
		shutdownServer(server)
		return fmt.Errorf("인증 시간 초과")
	}
}

// generateCodeVerifier는 PKCE용 코드 검증자를 생성합니다.
func generateCodeVerifier() (string, error) {
	// 랜덤 바이트 생성 (32바이트 = 256비트)
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// Base64 URL 인코딩
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateRandomString은 지정된 길이의 랜덤 문자열을 생성합니다.
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}

// GetAuthorizationURLWithPKCE는 PKCE를 지원하는 인증 URL을 생성합니다.
func (g *GraphHelper) GetAuthorizationURLWithPKCE(state, codeVerifier string) string {
	// Microsoft OAuth 엔드포인트 URL 생성
	redirectURI := "http://localhost:8080/callback"

	authURL := fmt.Sprintf(
		"%s/authorize?"+
			"client_id=%s"+
			"&response_type=code"+
			"&redirect_uri=%s"+
			"&response_mode=query"+
			"&scope=%s"+
			"&state=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256",
		g.oauthEndpoint,
		g.clientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape(strings.Join(g.scopes, " ")+" offline_access"),
		url.QueryEscape(state),
		url.QueryEscape(generateCodeChallenge(codeVerifier)),
	)

	return authURL
}

// generateCodeChallenge는 코드 검증자로부터 코드 챌린지를 생성합니다.
func generateCodeChallenge(codeVerifier string) string {
	// PKCE에 따라 코드 검증자의 SHA256 해시를 생성하고 base64url로 인코딩
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// startLocalServer는 리디렉션을 처리할 로컬 HTTP 서버를 시작합니다.
func startLocalServer(expectedState string, resultChan chan AuthResult) (*http.Server, error) {
	var server *http.Server
	var once sync.Once

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// 상태 검증
		state := r.URL.Query().Get("state")
		if state != expectedState {
			resultChan <- AuthResult{Error: "상태 토큰 불일치"}
			w.Write([]byte("인증 실패: 상태 토큰 불일치"))
			return
		}

		// 코드 추출
		code := r.URL.Query().Get("code")
		if code == "" {
			error := r.URL.Query().Get("error")
			errorDesc := r.URL.Query().Get("error_description")
			resultChan <- AuthResult{Error: fmt.Sprintf("%s: %s", error, errorDesc)}
			w.Write([]byte(fmt.Sprintf("인증 실패: %s - %s", error, errorDesc)))
			return
		}

		// 성공 응답
		w.Write([]byte("인증 성공! 이 창을 닫으셔도 됩니다."))

		// 결과 전송 (한 번만)
		once.Do(func() {
			resultChan <- AuthResult{Code: code, State: state}
		})
	})

	server = &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("서버 오류: %v\n", err)
		}
	}()

	return server, nil
}

// openBrowser는 기본 브라우저를 열어 지정된 URL로 이동합니다.
func openBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("지원되지 않는 플랫폼")
	}

	return err
}

// shutdownServer는 HTTP 서버를 안전하게 종료합니다.
func shutdownServer(server *http.Server) {
	if server != nil {
		// 5초 타임아웃으로 서버 종료
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}
}

// HandleRedirectCallbackWithPKCE는 PKCE를 사용하여 인증 코드를 토큰으로 교환합니다.
func (g *GraphHelper) HandleRedirectCallbackWithPKCE(userID, code, codeVerifier string) error {
	// 코드를 사용하여 액세스 토큰 및 리프레시 토큰 획득
	tokenResp, err := g.exchangeCodeForTokenWithPKCE(code, codeVerifier)
	if err != nil {
		return fmt.Errorf("token exchange failed: %v", err)
	}

	// 토큰 저장
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	g.storeMutex.Lock()
	userToken := UserToken{
		UserID:       userID,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}
	g.tokenStore[userID] = userToken
	g.storeMutex.Unlock()

	// DB에 토큰 저장 (DB가 초기화된 경우)
	if g.tokenStorage != nil {
		if err := g.tokenStorage.SaveToken(userToken); err != nil {
			log.Printf("경고: DB에 토큰 저장 실패: %v", err)
		} else {
			fmt.Printf("사용자 %s의 토큰이 DB에 저장되었습니다\n", userID)
		}
	}

	fmt.Printf("사용자 %s 인증 성공\n", userID)
	return nil
}

// exchangeCodeForTokenWithPKCE는 PKCE를 사용하여 인증 코드를 액세스 토큰으로 교환합니다.
func (g *GraphHelper) exchangeCodeForTokenWithPKCE(code, codeVerifier string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/token", g.oauthEndpoint)
	redirectURI := "http://localhost:8080/callback"

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("scope", strings.Join(g.scopes, " "))
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", codeVerifier)

	if g.clientSecret != "" {
		data.Set("client_secret", g.clientSecret)
	}

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}
