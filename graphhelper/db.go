package graphhelper

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TokenStorage는 SQLite를 사용하여 토큰을 저장하고 로드하는 구현을 제공합니다.
type TokenStorage struct {
	db *sql.DB
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
		access_token TEXT NOT NULL,
		refresh_token TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		scope TEXT NOT NULL,
		token_type TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("테이블 생성 실패: %v", err)
	}

	return &TokenStorage{db: db}, nil
}

// Close는 데이터베이스 연결을 닫습니다.
func (ts *TokenStorage) Close() error {
	return ts.db.Close()
}

// SaveToken은 사용자 토큰을 데이터베이스에 저장합니다.
func (ts *TokenStorage) SaveToken(token UserToken) error {
	// 기존 토큰이 있는지 확인
	var exists bool
	err := ts.db.QueryRow("SELECT 1 FROM user_tokens WHERE user_id = ?", token.UserID).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("토큰 조회 중 오류: %v", err)
	}

	// 현재 시간
	now := time.Now()

	// 만료 시간을 RFC3339 형식의 문자열로 변환
	expiresAtStr := token.ExpiresAt.Format(time.RFC3339)

	if err == sql.ErrNoRows {
		// 토큰 추가
		insertSQL := `
		INSERT INTO user_tokens (
			user_id, access_token, refresh_token, expires_at, scope, token_type, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`
		_, err = ts.db.Exec(
			insertSQL,
			token.UserID,
			token.AccessToken,
			token.RefreshToken,
			expiresAtStr,
			token.Scope,
			token.TokenType,
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
			access_token = ?,
			refresh_token = ?,
			expires_at = ?,
			scope = ?,
			token_type = ?,
			updated_at = ?
		WHERE user_id = ?
		`
		_, err = ts.db.Exec(
			updateSQL,
			token.AccessToken,
			token.RefreshToken,
			expiresAtStr,
			token.Scope,
			token.TokenType,
			now,
			token.UserID,
		)
		if err != nil {
			return fmt.Errorf("토큰 업데이트 실패: %v", err)
		}
	}

	return nil
}

// LoadToken은 사용자 ID로 토큰을 로드합니다.
func (ts *TokenStorage) LoadToken(userID string) (*UserToken, error) {
	query := `
	SELECT user_id, access_token, refresh_token, expires_at, scope, token_type
	FROM user_tokens
	WHERE user_id = ?
	`
	row := ts.db.QueryRow(query, userID)

	var token UserToken
	var expiresAt string // SQLite에서 시간을 문자열로 처리

	err := row.Scan(
		&token.UserID,
		&token.AccessToken,
		&token.RefreshToken,
		&expiresAt,
		&token.Scope,
		&token.TokenType,
	)

	if err == sql.ErrNoRows {
		return nil, nil // 토큰 없음
	} else if err != nil {
		return nil, fmt.Errorf("토큰 로드 실패: %v", err)
	}

	// 여러 가능한 시간 형식으로 파싱 시도
	var parsedTime time.Time
	formats := []string{
		time.RFC3339,                          // "2006-01-02T15:04:05Z07:00"
		"2006-01-02 15:04:05.999999999-07:00", // 원래 형식
		"2006-01-02T15:04:05.999999999Z07:00", // 다른 가능한 형식
	}

	var parseErr error
	for _, format := range formats {
		parsedTime, parseErr = time.Parse(format, expiresAt)
		if parseErr == nil {
			break
		}
	}

	if parseErr != nil {
		return nil, fmt.Errorf("토큰 만료 시간 파싱 실패: %v (시간: %s)", parseErr, expiresAt)
	}

	token.ExpiresAt = parsedTime

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
