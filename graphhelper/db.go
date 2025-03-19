package graphhelper

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TokenStorage는 SQLite를 사용하여 토큰을 저장하고 로드하는 구현을 제공합니다.
type TokenStorage struct {
	db     *sql.DB
	crypto *TokenCrypto // 토큰 암호화 및 복호화를 위한 객체
}

// NewTokenStorage는 새로운 TokenStorage 인스턴스를 생성합니다.
func NewTokenStorage(dbPath string) (*TokenStorage, error) {
	// SQLite 데이터베이스 연결
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("데이터베이스 연결 실패: %v", err)
	}

	// 토큰 테이블 생성
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS user_tokens (
		user_id TEXT PRIMARY KEY,
		encrypted_token TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("테이블 생성 실패: %v", err)
	}

	// 암호화 인스턴스 생성
	crypto, err := NewTokenCrypto()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("암호화 초기화 실패: %v", err)
	}

	return &TokenStorage{db: db, crypto: crypto}, nil
}

// Close는 데이터베이스 연결을 닫습니다.
func (ts *TokenStorage) Close() error {
	return ts.db.Close()
}

// SaveToken은 사용자 토큰을 암호화하여 데이터베이스에 저장합니다.
func (ts *TokenStorage) SaveToken(token UserToken) error {
	// 토큰을 JSON으로 직렬화
	tokenJson, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("토큰 직렬화 실패: %v", err)
	}

	// 토큰 데이터 암호화
	encryptedToken, err := ts.crypto.Encrypt(tokenJson)
	if err != nil {
		return fmt.Errorf("토큰 암호화 실패: %v", err)
	}

	// 기존 토큰이 있는지 확인
	var exists bool
	err = ts.db.QueryRow("SELECT 1 FROM user_tokens WHERE user_id = ?", token.UserID).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("토큰 조회 중 오류: %v", err)
	}

	// 현재 시간
	now := time.Now()

	if err == sql.ErrNoRows {
		// 토큰 추가
		insertSQL := `
		INSERT INTO user_tokens (
			user_id, encrypted_token, created_at, updated_at
		) VALUES (?, ?, ?, ?)
		`
		_, err = ts.db.Exec(
			insertSQL,
			token.UserID,
			encryptedToken,
			now,
			now,
		)
		if err != nil {
			return fmt.Errorf("토큰 저장 실패: %v", err)
		}
	} else {
		// 토큰 업데이트
		updateSQL := `
		UPDATE user_tokens SET
			encrypted_token = ?,
			updated_at = ?
		WHERE user_id = ?
		`
		_, err = ts.db.Exec(
			updateSQL,
			encryptedToken,
			now,
			token.UserID,
		)
		if err != nil {
			return fmt.Errorf("토큰 업데이트 실패: %v", err)
		}
	}

	return nil
}

// LoadToken은 사용자 ID로 암호화된 토큰을 로드하고 복호화합니다.
func (ts *TokenStorage) LoadToken(userID string) (*UserToken, error) {
	query := `
	SELECT encrypted_token
	FROM user_tokens
	WHERE user_id = ?
	`
	row := ts.db.QueryRow(query, userID)

	var encryptedToken string

	err := row.Scan(&encryptedToken)

	if err == sql.ErrNoRows {
		return nil, nil // 토큰 없음
	} else if err != nil {
		return nil, fmt.Errorf("토큰 로드 실패: %v", err)
	}

	// 암호화된 토큰 복호화
	tokenJson, err := ts.crypto.Decrypt(encryptedToken)
	if err != nil {
		return nil, fmt.Errorf("토큰 복호화 실패: %v", err)
	}

	// JSON 파싱
	var token UserToken
	if err := json.Unmarshal(tokenJson, &token); err != nil {
		return nil, fmt.Errorf("토큰 역직렬화 실패: %v", err)
	}

	return &token, nil
}

// ListUsers는 저장된 모든 사용자 ID를 반환합니다.
func (ts *TokenStorage) ListUsers() ([]string, error) {
	rows, err := ts.db.Query("SELECT user_id FROM user_tokens")
	if err != nil {
		return nil, fmt.Errorf("사용자 목록 조회 실패: %v", err)
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("사용자 ID 추출 실패: %v", err)
		}
		users = append(users, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("사용자 목록 읽기 실패: %v", err)
	}

	return users, nil
}

// DeleteToken은 지정된 사용자의 토큰을 삭제합니다.
func (ts *TokenStorage) DeleteToken(userID string) error {
	_, err := ts.db.Exec("DELETE FROM user_tokens WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("토큰 삭제 실패: %v", err)
	}
	return nil
}

// InitDB는 GraphHelper에서 토큰 스토리지를 초기화합니다
func (g *GraphHelper) InitDB(dbPath string) error {
	storage, err := NewTokenStorage(dbPath)
	if err != nil {
		return err
	}
	g.tokenStorage = storage

	// 저장된 모든 토큰을 메모리로 로드
	users, err := storage.ListUsers()
	if err != nil {
		return err
	}

	for _, userID := range users {
		token, err := storage.LoadToken(userID)
		if err != nil {
			log.Printf("사용자 %s의 토큰 로드 실패: %v", userID, err)
			continue
		}

		// 토큰이 만료되었으면 리프레시 시도
		if time.Until(token.ExpiresAt) < 5*time.Minute {
			log.Printf("사용자 %s의 토큰이 만료되어 리프레시 시도합니다", userID)
			tokenResp, err := g.refreshToken(token.RefreshToken)
			if err != nil {
				// 리프레시 토큰도 만료된 경우
				if isRefreshTokenExpired(err) {
					log.Printf("사용자 %s의 리프레시 토큰이 만료되었습니다. 재인증이 필요합니다.", userID)
					// 토큰을 메모리에 로드하지 않음
					continue
				}
				log.Printf("사용자 %s의 토큰 리프레시 실패: %v", userID, err)
				continue
			}

			// 새 토큰으로 업데이트
			expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			token.AccessToken = tokenResp.AccessToken
			token.RefreshToken = tokenResp.RefreshToken
			token.ExpiresAt = expiresAt
			token.Scope = tokenResp.Scope
			token.TokenType = tokenResp.TokenType

			// DB에 업데이트된 토큰 저장
			if err := storage.SaveToken(*token); err != nil {
				log.Printf("사용자 %s의 토큰 저장 실패: %v", userID, err)
				continue
			}
		}

		// 메모리에 토큰 설정
		g.storeMutex.Lock()
		g.tokenStore[userID] = *token
		g.storeMutex.Unlock()
		log.Printf("사용자 %s의 토큰이 메모리에 로드되었습니다", userID)
	}

	return nil
}

// isRefreshTokenExpired는 에러 메시지를 확인하여 리프레시 토큰이 만료되었는지 판단합니다.
func isRefreshTokenExpired(err error) bool {
	// Microsoft OAuth 에러 메시지 확인
	errorMsg := err.Error()
	refreshTokenExpiredErrors := []string{
		"refresh token has expired",
		"AADSTS700082",         // 리프레시 토큰 만료
		"AADSTS50173",          // 리프레시 토큰 만료
		"invalid_grant",        // 일반적인 OAuth 에러 코드
		"interaction_required", // 사용자 상호작용 필요
	}

	for _, errText := range refreshTokenExpiredErrors {
		if strings.Contains(errorMsg, errText) {
			return true
		}
	}
	return false
}

// SaveUserTokenToDB는 현재 메모리에 있는 사용자 토큰을 DB에 저장합니다
func (g *GraphHelper) SaveUserTokenToDB(userID string) error {
	if g.tokenStorage == nil {
		return fmt.Errorf("토큰 스토리지가 초기화되지 않았습니다")
	}

	g.storeMutex.Lock()
	token, exists := g.tokenStore[userID]
	g.storeMutex.Unlock()

	if !exists {
		return fmt.Errorf("사용자 %s의 토큰이 메모리에 없습니다", userID)
	}

	return g.tokenStorage.SaveToken(token)
}

// LoadUserTokenFromDB는 DB에서 사용자 토큰을 로드하여 메모리에 설정합니다
func (g *GraphHelper) LoadUserTokenFromDB(userID string) error {
	if g.tokenStorage == nil {
		return fmt.Errorf("토큰 스토리지가 초기화되지 않았습니다")
	}

	token, err := g.tokenStorage.LoadToken(userID)
	if err != nil {
		return err
	}

	if token == nil {
		return fmt.Errorf("사용자 %s의 토큰을 찾을 수 없습니다", userID)
	}

	// 토큰이 만료되었으면 리프레시 시도
	if time.Until(token.ExpiresAt) < 5*time.Minute {
		fmt.Printf("사용자 %s의 토큰이 만료되어 리프레시합니다\n", userID)
		tokenResp, err := g.refreshToken(token.RefreshToken)
		if err != nil {
			// 리프레시 토큰도 만료된 경우
			if isRefreshTokenExpired(err) {
				g.tokenStorage.DeleteToken(userID)
				return fmt.Errorf("리프레시 토큰이 만료되었습니다. 재인증이 필요합니다")
			}
			return fmt.Errorf("토큰 리프레시 실패: %v", err)
		}

		// 새 토큰으로 업데이트
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		token.AccessToken = tokenResp.AccessToken
		token.RefreshToken = tokenResp.RefreshToken
		token.ExpiresAt = expiresAt
		token.Scope = tokenResp.Scope
		token.TokenType = tokenResp.TokenType

		// DB에 업데이트된 토큰 저장
		if err := g.tokenStorage.SaveToken(*token); err != nil {
			return fmt.Errorf("업데이트된 토큰 저장 실패: %v", err)
		}
	}

	// 메모리에 토큰 설정
	g.storeMutex.Lock()
	g.tokenStore[userID] = *token
	g.storeMutex.Unlock()

	fmt.Printf("사용자 %s의 토큰이 DB에서 로드되었습니다\n", userID)
	return nil
}

// ListDBUsers는 DB에 저장된 모든 사용자 ID를 반환합니다
func (g *GraphHelper) ListDBUsers() ([]string, error) {
	if g.tokenStorage == nil {
		return nil, fmt.Errorf("토큰 스토리지가 초기화되지 않았습니다")
	}

	return g.tokenStorage.ListUsers()
}

// DeleteUserToken은 특정 사용자의 토큰을 DB에서 삭제합니다
func (g *GraphHelper) DeleteUserToken(userID string) error {
	if g.tokenStorage == nil {
		return fmt.Errorf("토큰 스토리지가 초기화되지 않았습니다")
	}

	// 데이터베이스에서 삭제
	err := g.tokenStorage.DeleteToken(userID)
	if err != nil {
		return err
	}

	// 메모리에서도 삭제
	g.storeMutex.Lock()
	delete(g.tokenStore, userID)
	g.storeMutex.Unlock()

	fmt.Printf("사용자 %s의 토큰이 삭제되었습니다\n", userID)
	return nil
}
