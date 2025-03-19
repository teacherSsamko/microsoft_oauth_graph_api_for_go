package graphhelper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32 // secretbox 키 크기
	nonceSize = 24 // secretbox nonce 크기
)

var defaultEncryptionKey = []byte("defaultSecretKeyFor1234567890123456") // 32바이트

// TokenCrypto는 토큰 암호화 및 복호화를 담당합니다.
type TokenCrypto struct {
	key [keySize]byte
}

// NewTokenCrypto는 새로운 TokenCrypto 인스턴스를 생성합니다.
func NewTokenCrypto() (*TokenCrypto, error) {
	var keyBytes [keySize]byte

	// 환경 변수에서 암호화 키 로드 시도
	envKey := os.Getenv("TOKEN_ENCRYPTION_KEY")
	if envKey != "" {
		// 16진수 문자열 파싱
		keySlice, err := hex.DecodeString(envKey)
		if err != nil || len(keySlice) != keySize {
			return nil, fmt.Errorf("잘못된 암호화 키 형식: %v", err)
		}
		copy(keyBytes[:], keySlice)
	} else {
		// 환경 변수가 설정되지 않았으면 기본 키 사용
		copy(keyBytes[:], defaultEncryptionKey)
	}

	return &TokenCrypto{key: keyBytes}, nil
}

// Encrypt는 평문 데이터를 암호화합니다.
func (tc *TokenCrypto) Encrypt(plaintext []byte) (string, error) {
	// 랜덤 nonce 생성
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	// 암호화
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, &tc.key)

	// 결과를 base64로 인코딩하여 문자열로 반환
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt는 암호화된 데이터를 복호화합니다.
func (tc *TokenCrypto) Decrypt(ciphertext string) ([]byte, error) {
	// base64 디코딩
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// 데이터 길이 검증
	if len(encrypted) < nonceSize {
		return nil, errors.New("암호화된 데이터가 너무 짧습니다")
	}

	// nonce 추출
	var nonce [nonceSize]byte
	copy(nonce[:], encrypted[:nonceSize])

	// 복호화
	decrypted, ok := secretbox.Open(nil, encrypted[nonceSize:], &nonce, &tc.key)
	if !ok {
		return nil, errors.New("복호화 실패: 데이터가 손상되었거나 잘못된 키입니다")
	}

	return decrypted, nil
}

// GenerateEncryptionKey는 새로운 암호화 키를 생성하여 16진수 문자열로 반환합니다.
func GenerateEncryptionKey() (string, error) {
	var key [keySize]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}
