package graphhelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// UserToken은 사용자 토큰 정보를 저장합니다.
type UserToken struct {
	UserID       string    `json:"user_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope"`
	TokenType    string    `json:"token_type"`
}

// DeviceCodeResponse는 디바이스 코드 인증 첫 단계 응답입니다.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Message                 string `json:"message"`
}

// TokenResponse는 토큰 요청에 대한 응답입니다.
type TokenResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo는 사용자 정보를 저장합니다.
type UserInfo struct {
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// GetDisplayName은 사용자 표시 이름을 반환합니다.
func (u *UserInfo) GetDisplayName() *string {
	return &u.DisplayName
}

// GetMail은 사용자 이메일을 반환합니다.
func (u *UserInfo) GetMail() *string {
	if u.Mail == "" {
		return nil
	}
	return &u.Mail
}

// GetUserPrincipalName은 사용자 계정 이름을 반환합니다.
func (u *UserInfo) GetUserPrincipalName() *string {
	return &u.UserPrincipalName
}

// EmailMessage는 이메일 메시지 정보를 저장합니다.
type EmailMessage struct {
	ID               string    `json:"id"`
	Subject          string    `json:"subject"`
	From             Recipient `json:"from"`
	ReceivedDateTime string    `json:"receivedDateTime"`
	IsRead           bool      `json:"isRead"`
}

// GetSubject는 이메일 제목을 반환합니다.
func (e *EmailMessage) GetSubject() *string {
	return &e.Subject
}

// GetFrom은 이메일 발신자를 반환합니다.
func (e *EmailMessage) GetFrom() *Recipient {
	return &e.From
}

// GetIsRead는 이메일 읽음 여부를 반환합니다.
func (e *EmailMessage) GetIsRead() *bool {
	return &e.IsRead
}

// GetReceivedDateTime은 이메일 수신 시간을 파싱하여 반환합니다.
func (e *EmailMessage) GetReceivedDateTime() time.Time {
	t, _ := time.Parse(time.RFC3339, e.ReceivedDateTime)
	return t
}

// Recipient는 이메일 송수신자 정보를 저장합니다.
type Recipient struct {
	EmailAddress EmailAddress `json:"emailAddress"`
}

// GetEmailAddress는 이메일 주소 정보를 반환합니다.
func (r *Recipient) GetEmailAddress() *EmailAddress {
	return &r.EmailAddress
}

// EmailAddress는 이메일 주소 정보를 저장합니다.
type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

// GetName은 이메일 주소 이름을 반환합니다.
func (e *EmailAddress) GetName() *string {
	return &e.Name
}

// GetAddress는 이메일 주소를 반환합니다.
func (e *EmailAddress) GetAddress() *string {
	return &e.Address
}

// InboxResponse는 받은 편지함 응답을 저장합니다.
type InboxResponse struct {
	Value         []EmailMessage `json:"value"`
	OdataNextLink *string        `json:"@odata.nextLink,omitempty"`
}

// GetValue는 받은 편지함 메시지 목록을 반환합니다.
func (i *InboxResponse) GetValue() []EmailMessage {
	return i.Value
}

// GetOdataNextLink는 다음 페이지 링크를 반환합니다.
func (i *InboxResponse) GetOdataNextLink() *string {
	return i.OdataNextLink
}

type GraphHelper struct {
	clientID      string
	clientSecret  string
	tenantID      string
	scopes        []string
	tokenStore    map[string]UserToken // 사용자별 토큰 저장 (메모리 예시)
	storeMutex    sync.Mutex           // 동시성 제어
	oauthEndpoint string               // OAuth 엔드포인트
	defaultUserID string               // 기본 사용자 ID (호환성 유지용)
}

func NewGraphHelper() (*GraphHelper, error) {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	tenantID := os.Getenv("TENANT_ID")
	scopesStr := os.Getenv("GRAPH_USER_SCOPES")
	scopes := strings.Split(scopesStr, ",")

	return &GraphHelper{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tenantID:      tenantID,
		scopes:        scopes,
		tokenStore:    make(map[string]UserToken),
		oauthEndpoint: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenantID),
		defaultUserID: "default_user", // 기본 사용자 ID 설정
	}, nil
}

// InitializeGraphForUserAuth 함수는 호환성을 위해 유지하며 기본 사용자 인증을 수행합니다
func (g *GraphHelper) InitializeGraphForUserAuth() error {
	// 기존 SDK 기반 초기화 대신 OAuth 2.0 직접 인증 수행
	return g.AuthenticateUser(g.defaultUserID)
}

// AuthenticateUser는 디바이스 코드 인증 흐름을 시작합니다.
func (g *GraphHelper) AuthenticateUser(userID string) error {
	// 디바이스 코드 요청
	deviceCodeResp, err := g.requestDeviceCode()
	if err != nil {
		return fmt.Errorf("device code request failed: %v", err)
	}

	// 사용자에게 인증 안내 메시지 출력
	fmt.Println("디바이스 코드 인증을 시작합니다:")
	fmt.Println(deviceCodeResp.Message)

	// 사용자가 인증을 완료할 때까지 폴링
	tokenResp, err := g.pollForToken(deviceCodeResp)
	if err != nil {
		return fmt.Errorf("token request failed: %v", err)
	}

	// 토큰 저장
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	g.storeMutex.Lock()
	defer g.storeMutex.Unlock()
	fmt.Println("tokenResp.AccessToken", tokenResp.AccessToken)
	fmt.Println("tokenResp.RefreshToken", tokenResp.RefreshToken)
	g.tokenStore[userID] = UserToken{
		UserID:       userID,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}

	fmt.Printf("사용자 %s 인증 성공\n", userID)
	return nil
}

// requestDeviceCode는 디바이스 코드 인증 첫 단계를 요청합니다.
func (g *GraphHelper) requestDeviceCode() (*DeviceCodeResponse, error) {
	endpoint := fmt.Sprintf("%s/devicecode", g.oauthEndpoint)

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("scope", strings.Join(g.scopes, " "))

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device code request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var deviceCodeResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCodeResp); err != nil {
		return nil, err
	}

	return &deviceCodeResp, nil
}

// pollForToken은 사용자가 인증을 완료할 때까지 토큰 엔드포인트를 폴링합니다.
func (g *GraphHelper) pollForToken(deviceCodeResp *DeviceCodeResponse) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/token", g.oauthEndpoint)

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCodeResp.DeviceCode)

	// 타임아웃 설정
	timeout := time.Now().Add(time.Duration(deviceCodeResp.ExpiresIn) * time.Second)

	// 폴링 간격 설정 (최소 5초)
	interval := deviceCodeResp.Interval
	if interval < 5 {
		interval = 5
	}

	for time.Now().Before(timeout) {
		resp, err := http.PostForm(endpoint, data)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			var tokenResp TokenResponse
			if err := json.Unmarshal(body, &tokenResp); err != nil {
				return nil, err
			}
			return &tokenResp, nil
		}

		// 아직 인증되지 않았으면 오류 응답 확인
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}

		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, err
		}

		// 아직 인증 대기 중인 경우
		if errorResp.Error == "authorization_pending" {
			time.Sleep(time.Duration(interval) * time.Second)
			fmt.Println("authorization_pending")
			continue
		}

		// 다른 오류인 경우 종료
		return nil, fmt.Errorf("auth error: %s - %s", errorResp.Error, errorResp.ErrorDescription)
	}

	return nil, fmt.Errorf("device code authentication timed out")
}

// GetUserTokenById는 특정 사용자의 토큰을 조회하거나 필요시 리프레시합니다.
func (g *GraphHelper) GetUserTokenById(userID string) (string, error) {
	g.storeMutex.Lock()
	storedToken, exists := g.tokenStore[userID]
	g.storeMutex.Unlock()

	// 토큰이 존재하지 않으면 인증 필요
	if !exists {
		return "", fmt.Errorf("user %s not authenticated, please call AuthenticateUser first", userID)
	}

	// 토큰이 만료되었거나 만료 임박한 경우 리프레시
	if time.Until(storedToken.ExpiresAt) < 5*time.Minute {
		fmt.Println("액세스 토큰이 곧 만료됩니다. 리프레시 토큰으로 새로운 토큰을 얻습니다...")

		// 리프레시 토큰으로 새 토큰 얻기
		tokenResp, err := g.refreshToken(storedToken.RefreshToken)
		if err != nil {
			return "", fmt.Errorf("token refresh failed: %v", err)
		}

		// 새 토큰 저장
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

		g.storeMutex.Lock()
		fmt.Println("tokenResp.RefreshToken", tokenResp.RefreshToken)
		g.tokenStore[userID] = UserToken{
			UserID:       userID,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ExpiresAt:    expiresAt,
			Scope:        tokenResp.Scope,
			TokenType:    tokenResp.TokenType,
		}
		storedToken = g.tokenStore[userID]
		g.storeMutex.Unlock()

		fmt.Println("토큰이 성공적으로 갱신되었습니다.")
	}

	return storedToken.AccessToken, nil
}

// refreshToken은 리프레시 토큰을 사용하여 새 액세스 토큰을 획득합니다.
func (g *GraphHelper) refreshToken(refreshToken string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/token", g.oauthEndpoint)

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", strings.Join(g.scopes, " "))

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// SaveUserToken은 사용자 토큰을 DB에 저장하기 위해 직렬화합니다.
func (g *GraphHelper) SaveUserToken(userID string) ([]byte, error) {
	g.storeMutex.Lock()
	defer g.storeMutex.Unlock()

	storedToken, exists := g.tokenStore[userID]
	if !exists {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	// 토큰 정보를 직렬화
	tokenBytes, err := json.Marshal(storedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize token: %v", err)
	}

	// 실제 구현에서는 여기에 DB에 저장하는 코드를 추가
	// 예: saveToDatabase(userID, tokenBytes)

	return tokenBytes, nil
}

// LoadUserToken은 DB에서 불러온 토큰 정보를 사용하여 인증 세션을 복구합니다.
func (g *GraphHelper) LoadUserToken(tokenBytes []byte) error {
	var token UserToken

	// 바이트 배열에서 토큰 정보 역직렬화
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return fmt.Errorf("failed to deserialize token: %v", err)
	}

	// 토큰이 만료되었으면 리프레시 시도
	if time.Now().After(token.ExpiresAt) {
		fmt.Println("저장된 액세스 토큰이 만료되었습니다. 리프레시 토큰으로 갱신합니다...")

		tokenResp, err := g.refreshToken(token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to refresh token: %v", err)
		}

		// 새 토큰으로 업데이트
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		token.AccessToken = tokenResp.AccessToken
		token.RefreshToken = tokenResp.RefreshToken
		token.ExpiresAt = expiresAt
		token.Scope = tokenResp.Scope
		token.TokenType = tokenResp.TokenType
	}

	// 토큰 저장
	g.storeMutex.Lock()
	g.tokenStore[token.UserID] = token
	g.storeMutex.Unlock()

	fmt.Printf("사용자 %s의 세션이 복구되었습니다.\n", token.UserID)
	return nil
}

// GetUserRefreshToken은 기존 함수와의 호환성을 위한 함수입니다
func (g *GraphHelper) GetUserRefreshToken() (*string, error) {
	g.storeMutex.Lock()
	defer g.storeMutex.Unlock()

	storedToken, exists := g.tokenStore[g.defaultUserID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	token := storedToken.RefreshToken
	return &token, nil
}

// GetUserToken은 기존 함수와의 호환성을 위한 함수입니다
func (g *GraphHelper) GetUserToken() (*string, error) {
	token, err := g.GetUserTokenById(g.defaultUserID)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetGraphData는 액세스 토큰을 사용하여 Graph API를 직접 호출합니다
func (g *GraphHelper) GetGraphData(endpoint string, accessToken string) ([]byte, error) {
	// Graph API 엔드포인트 URL 생성
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s", endpoint)

	// HTTP 요청 생성
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 인증 헤더 추가
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	// 요청 실행
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 응답 처리
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("graph api request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// 응답 본문 읽기
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// PostGraphData는 액세스 토큰을 사용하여 Graph API에 POST 요청을 보냅니다
func (g *GraphHelper) PostGraphData(endpoint string, accessToken string, data interface{}) ([]byte, error) {
	// Graph API 엔드포인트 URL 생성
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s", endpoint)

	// 요청 바디 생성
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// HTTP 요청 생성
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// 인증 헤더 추가
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	// 요청 실행
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 응답 처리
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("graph api request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetUser는 사용자 정보를 가져옵니다 (기존 SDK 호환성 유지)
func (g *GraphHelper) GetUser() (*UserInfo, error) {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(g.defaultUserID)
	if err != nil {
		return nil, err
	}

	// Graph API 호출
	data, err := g.GetGraphData("me?$select=displayName,mail,userPrincipalName", accessToken)
	if err != nil {
		return nil, err
	}

	// 응답 파싱
	var userInfo UserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// GetInbox는 받은 편지함을 가져옵니다 (기존 SDK 호환성 유지)
func (g *GraphHelper) GetInbox() (*InboxResponse, error) {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(g.defaultUserID)
	if err != nil {
		return nil, err
	}

	// Graph API 호출
	endpoint := "me/mailFolders/inbox/messages?$select=from,isRead,receivedDateTime,subject&$top=5&$orderby=receivedDateTime DESC"
	data, err := g.GetGraphData(endpoint, accessToken)
	if err != nil {
		return nil, err
	}

	// 응답 파싱
	var inboxResponse InboxResponse
	if err := json.Unmarshal(data, &inboxResponse); err != nil {
		return nil, err
	}

	return &inboxResponse, nil
}

// SendMail은 이메일을 보냅니다 (기존 SDK 호환성 유지)
func (g *GraphHelper) SendMail(subject, body, recipient *string) error {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(g.defaultUserID)
	if err != nil {
		return err
	}

	// 메일 데이터 구성
	mailData := map[string]interface{}{
		"message": map[string]interface{}{
			"subject": *subject,
			"body": map[string]interface{}{
				"contentType": "Text",
				"content":     *body,
			},
			"toRecipients": []map[string]interface{}{
				{
					"emailAddress": map[string]interface{}{
						"address": *recipient,
					},
				},
			},
		},
	}

	// Graph API 호출
	_, err = g.PostGraphData("me/sendMail", accessToken, mailData)
	return err
}

// 아래는 신규 기능을 위한 추가 메서드들 (userID를 매개변수로 받는 버전)

// GetUserByID는 특정 사용자의 정보를 가져옵니다
func (g *GraphHelper) GetUserByID(userID string) (*UserInfo, error) {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(userID)
	if err != nil {
		return nil, err
	}

	// Graph API 호출
	data, err := g.GetGraphData("me?$select=displayName,mail,userPrincipalName", accessToken)
	if err != nil {
		return nil, err
	}

	// 응답 파싱
	var userInfo UserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// GetInboxByID는 특정 사용자의 받은 편지함을 가져옵니다
func (g *GraphHelper) GetInboxByID(userID string) (*InboxResponse, error) {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(userID)
	if err != nil {
		return nil, err
	}

	// Graph API 호출
	endpoint := "me/mailFolders/inbox/messages?$select=from,isRead,receivedDateTime,subject&$top=5&$orderby=receivedDateTime DESC"
	data, err := g.GetGraphData(endpoint, accessToken)
	if err != nil {
		return nil, err
	}

	// 응답 파싱
	var inboxResponse InboxResponse
	if err := json.Unmarshal(data, &inboxResponse); err != nil {
		return nil, err
	}

	return &inboxResponse, nil
}

// SendMailByID는 특정 사용자로 이메일을 보냅니다
func (g *GraphHelper) SendMailByID(userID string, subject, body, recipient string) error {
	// 액세스 토큰 가져오기
	accessToken, err := g.GetUserTokenById(userID)
	if err != nil {
		return err
	}

	// 메일 데이터 구성
	mailData := map[string]interface{}{
		"message": map[string]interface{}{
			"subject": subject,
			"body": map[string]interface{}{
				"contentType": "Text",
				"content":     body,
			},
			"toRecipients": []map[string]interface{}{
				{
					"emailAddress": map[string]interface{}{
						"address": recipient,
					},
				},
			},
		},
	}

	// Graph API 호출
	_, err = g.PostGraphData("me/sendMail", accessToken, mailData)
	return err
}

// GetAuthorizationURL은 사용자 인증 URL을 생성합니다.
func (g *GraphHelper) GetAuthorizationURL(state string) string {
	// Microsoft OAuth 엔드포인트 URL 생성
	authURL := fmt.Sprintf(
		"%s/authorize?"+
			"client_id=%s"+
			"&response_type=code"+
			"&redirect_uri=%s"+
			"&response_mode=query"+
			"&scope=%s"+
			"&state=%s",
		g.oauthEndpoint,
		g.clientID,
		url.QueryEscape(os.Getenv("REDIRECT_URI")),
		url.QueryEscape(strings.Join(g.scopes, " ")),
		url.QueryEscape(state),
	)

	return authURL
}

// HandleRedirectCallback은 리디렉션 콜백을 처리하고 사용자 토큰을 획득합니다.
func (g *GraphHelper) HandleRedirectCallback(userID, code string) error {
	// 코드를 사용하여 액세스 토큰 및 리프레시 토큰 획득
	tokenResp, err := g.exchangeCodeForToken(code)
	if err != nil {
		return fmt.Errorf("token exchange failed: %v", err)
	}

	// 토큰 저장
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	g.storeMutex.Lock()
	defer g.storeMutex.Unlock()

	g.tokenStore[userID] = UserToken{
		UserID:       userID,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}

	fmt.Printf("사용자 %s 인증 성공\n", userID)
	return nil
}

// exchangeCodeForToken은 인증 코드를 액세스 토큰으로 교환합니다.
func (g *GraphHelper) exchangeCodeForToken(code string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/token", g.oauthEndpoint)

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("scope", strings.Join(g.scopes, " "))
	data.Set("code", code)
	data.Set("redirect_uri", os.Getenv("REDIRECT_URI"))
	data.Set("grant_type", "authorization_code")

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

// InitializeGraphClientForWeb은 웹 애플리케이션용 GraphHelper를 초기화합니다.
func NewGraphHelperForWeb() (*GraphHelper, error) {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET") // 웹 애플리케이션용 클라이언트 시크릿
	tenantID := os.Getenv("TENANT_ID")
	scopesStr := os.Getenv("GRAPH_USER_SCOPES")
	redirectURI := os.Getenv("REDIRECT_URI") // 리디렉션 URI

	scopes := strings.Split(scopesStr, ",")

	if clientSecret == "" {
		return nil, fmt.Errorf("CLIENT_SECRET 환경 변수가 설정되지 않았습니다")
	}

	if redirectURI == "" {
		return nil, fmt.Errorf("REDIRECT_URI 환경 변수가 설정되지 않았습니다")
	}

	return &GraphHelper{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tenantID:      tenantID,
		scopes:        scopes,
		tokenStore:    make(map[string]UserToken),
		oauthEndpoint: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenantID),
		defaultUserID: "default_user",
	}, nil
}
