package main

import (
	"fmt"
	"graphtutorial/graphhelper"
	"log"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	fmt.Println("Go Graph Tutorial")
	fmt.Println()

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	graphHelper, err := graphhelper.NewGraphHelper()
	if err != nil {
		log.Panicf("Error creating GraphHelper: %v\n", err)
	}

	// SQLite DB 초기화
	dbPath := "./tokens.db"
	err = graphHelper.InitDB(dbPath)
	if err != nil {
		log.Printf("경고: DB 초기화 실패: %v", err)
	} else {
		fmt.Println("SQLite DB가 초기화되었습니다:", dbPath)

		// 저장된 사용자 출력
		users, err := graphHelper.ListDBUsers()
		if err != nil {
			log.Printf("경고: 사용자 목록 조회 실패: %v", err)
		} else {
			if len(users) > 0 {
				fmt.Println("저장된 사용자:", users)
				fmt.Println("기존 사용자 인증을 사용할 수 있습니다 (메뉴 옵션 7)")
			} else {
				fmt.Println("저장된 사용자가 없습니다. 인증을 진행하세요 (메뉴 옵션 1 또는 2)")
			}
		}
	}

	var choice int64 = -1

	for {
		fmt.Println("\n애플리케이션 메뉴:")
		fmt.Println("0. 종료")
		fmt.Println("1. Device Code Flow 인증 - 다른 기기에서 코드 입력")
		fmt.Println("2. Authorization Code Flow 인증 - 브라우저 자동 열기")
		fmt.Println("3. 받은 편지함 목록 보기")
		fmt.Println("4. 이메일 보내기")
		fmt.Println("5. DB에서 사용자 토큰 로드")
		fmt.Println("6. 현재 사용자 토큰을 DB에 저장")
		fmt.Println("7. DB에 저장된 사용자 목록 표시")
		fmt.Println("8. 토큰 삭제")
		fmt.Println("9. 새 암호화 키 생성")

		_, err = fmt.Scanf("%d", &choice)
		if err != nil {
			choice = -1
		}

		switch choice {
		case 0:
			fmt.Println("Goodbye...")
		case 1:
			initializeGraphDeviceCode(graphHelper)
			greetUser(graphHelper)
		case 2:
			initializeGraphAuthCode(graphHelper)
			greetUser(graphHelper)
		case 3:
			listInbox(graphHelper)
		case 4:
			sendMail(graphHelper)
		case 5:
			loadUserTokenFromDB(graphHelper)
		case 6:
			saveUserTokenToDB(graphHelper)
		case 7:
			listDBUsers(graphHelper)
		case 8:
			deleteUserToken(graphHelper)
		case 9:
			generateNewEncryptionKey()
		default:
			fmt.Println("Invalid choice! Please try again.")
		}

		if choice == 0 {
			break
		}
	}
}

func initializeGraphDeviceCode(graphHelper *graphhelper.GraphHelper) {
	fmt.Println("Device Code Flow 인증을 시작합니다...")
	err := graphHelper.AuthenticateUser("default_user")
	if err != nil {
		log.Panicf("Error initializing Graph for user auth: %v\n", err)
	}
}

func initializeGraphAuthCode(graphHelper *graphhelper.GraphHelper) {
	fmt.Println("Authorization Code Flow 인증을 시작합니다...")
	err := graphHelper.AuthorizeWithBrowser("default_user")
	if err != nil {
		log.Panicf("Error initializing Graph with Authorization Code Flow: %v\n", err)
	}
}

func greetUser(graphHelper *graphhelper.GraphHelper) {
	user, err := graphHelper.GetUser()
	if err != nil {
		handleTokenError(err)
		return
	}

	fmt.Printf("Hello, %s!\n", *user.GetDisplayName())

	email := user.GetMail()
	if email == nil {
		email = user.GetUserPrincipalName()
	}

	fmt.Printf("Email: %s\n", *email)
	fmt.Println()
}

func displayAccessToken(graphHelper *graphhelper.GraphHelper) {
	token, err := graphHelper.GetUserToken()
	if err != nil {
		handleTokenError(err)
		return
	}

	// 토큰의 일부만 표시 (보안상의 이유로)
	tokenStr := *token
	if len(tokenStr) > 50 {
		tokenStr = tokenStr[:50] + "..." // 앞부분 50자만 표시
	}

	fmt.Printf("액세스 토큰: %s\n", tokenStr)
	fmt.Println()
}

func displayRefreshToken(graphHelper *graphhelper.GraphHelper) {
	token, err := graphHelper.GetUserRefreshToken()
	if err != nil {
		handleTokenError(err)
		return
	}

	// 토큰의 일부만 표시 (보안상의 이유로)
	tokenStr := *token
	if len(tokenStr) > 50 {
		tokenStr = tokenStr[:50] + "..." // 앞부분 50자만 표시
	}

	fmt.Println()
	fmt.Printf("리프레시 토큰: %s\n", tokenStr)
	fmt.Println()
}

func listInbox(graphHelper *graphhelper.GraphHelper) {
	messages, err := graphHelper.GetInbox()
	if err != nil {
		handleTokenError(err)
		return
	}

	location, err := time.LoadLocation("Local")
	if err != nil {
		log.Printf("타임존 로드 실패: %v\n", err)
		location = time.UTC
	}

	for _, message := range messages.GetValue() {
		fmt.Printf("Message: %s\n", *message.GetSubject())
		fmt.Printf("  From: %s\n", *message.GetFrom().GetEmailAddress().GetName())

		status := "Unknown"
		if *message.GetIsRead() {
			status = "Read"
		} else {
			status = "Unread"
		}
		fmt.Printf("  Status: %s\n", status)
		fmt.Printf("  Received: %s\n", message.GetReceivedDateTime().In(location).Format(time.RFC1123))
		fmt.Println()
	}

	nextLink := messages.GetOdataNextLink()

	fmt.Println()
	fmt.Printf("More messages available? %v\n", nextLink != nil)
	fmt.Println()
}

func sendMail(graphHelper *graphhelper.GraphHelper) {
	user, err := graphHelper.GetUser()
	if err != nil {
		handleTokenError(err)
		return
	}

	email := user.GetMail()
	if email == nil {
		email = user.GetUserPrincipalName()
	}

	subject := "Testing Microsoft Graph"
	body := "Hello world!"
	err = graphHelper.SendMail(&subject, &body, email)
	if err != nil {
		handleTokenError(err)
		return
	}

	fmt.Println("Mail sent successfully")
	fmt.Println()
}

func loadUserTokenFromDB(graphHelper *graphhelper.GraphHelper) {
	// 저장된 사용자 목록 조회
	users, err := graphHelper.ListDBUsers()
	if err != nil {
		log.Printf("사용자 목록 조회 실패: %v", err)
		return
	}

	if len(users) == 0 {
		fmt.Println("DB에 저장된 사용자가 없습니다.")
		return
	}

	// 사용자 목록 표시
	fmt.Println("DB에 저장된 사용자 목록:")
	for i, userID := range users {
		fmt.Printf("%d. %s\n", i+1, userID)
	}

	// 사용자 선택
	var choice int
	fmt.Print("로드할 사용자 번호를 선택하세요: ")
	_, err = fmt.Scanf("%d", &choice)
	if err != nil || choice < 1 || choice > len(users) {
		fmt.Println("잘못된 선택입니다.")
		return
	}

	userID := users[choice-1]

	// 토큰 로드
	err = graphHelper.LoadUserTokenFromDB(userID)
	if err != nil {
		// 리프레시 토큰 만료 체크
		if strings.Contains(err.Error(), "리프레시 토큰이 만료되었습니다") {
			fmt.Printf("사용자 %s의 리프레시 토큰이 만료되었습니다. 다시 인증해주세요.\n", userID)
			return
		}
		log.Printf("토큰 로드 실패: %v", err)
		return
	}

	// 기본 사용자 ID 업데이트
	graphHelper.SetDefaultUserID(userID)

	fmt.Printf("사용자 %s의 토큰이 메모리에 로드되었습니다.\n", userID)
}

func saveUserTokenToDB(graphHelper *graphhelper.GraphHelper) {
	// 사용자 ID 입력
	var userID string
	fmt.Print("저장할 사용자 ID를 입력하세요 (기본값 사용: default_user): ")
	_, err := fmt.Scanln(&userID)
	if err != nil || userID == "" {
		userID = "default_user"
	}

	// 토큰 저장
	err = graphHelper.SaveUserTokenToDB(userID)
	if err != nil {
		log.Printf("토큰 저장 실패: %v", err)
		return
	}

	fmt.Printf("사용자 %s의 토큰이 DB에 저장되었습니다.\n", userID)
}

func listDBUsers(graphHelper *graphhelper.GraphHelper) {
	// 저장된 사용자 목록 조회
	users, err := graphHelper.ListDBUsers()
	if err != nil {
		log.Printf("사용자 목록 조회 실패: %v", err)
		return
	}

	if len(users) == 0 {
		fmt.Println("DB에 저장된 사용자가 없습니다.")
		return
	}

	// 사용자 목록 표시
	fmt.Println("DB에 저장된 사용자 목록:")
	for i, userID := range users {
		fmt.Printf("%d. %s\n", i+1, userID)
	}
}

func deleteUserToken(graphHelper *graphhelper.GraphHelper) {
	// 저장된 사용자 목록 조회
	users, err := graphHelper.ListDBUsers()
	if err != nil {
		log.Printf("사용자 목록 조회 실패: %v", err)
		return
	}

	if len(users) == 0 {
		fmt.Println("DB에 저장된 사용자가 없습니다.")
		return
	}

	// 사용자 목록 표시
	fmt.Println("DB에 저장된 사용자 목록:")
	for i, userID := range users {
		fmt.Printf("%d. %s\n", i+1, userID)
	}

	// 사용자 선택
	var choice int
	fmt.Print("삭제할 사용자 번호를 선택하세요: ")
	_, err = fmt.Scanf("%d", &choice)
	if err != nil || choice < 1 || choice > len(users) {
		fmt.Println("잘못된 선택입니다.")
		return
	}

	userID := users[choice-1]

	// 확인
	var confirm string
	fmt.Printf("사용자 %s의 토큰을 삭제하시겠습니까? (y/n): ", userID)
	_, err = fmt.Scanf("%s", &confirm)
	if err != nil || (confirm != "y" && confirm != "Y") {
		fmt.Println("토큰 삭제가 취소되었습니다.")
		return
	}

	// 토큰 삭제
	err = graphHelper.DeleteUserToken(userID)
	if err != nil {
		log.Printf("토큰 삭제 실패: %v", err)
		return
	}

	fmt.Printf("사용자 %s의 토큰이 삭제되었습니다.\n", userID)
}

func generateNewEncryptionKey() {
	key, err := graphhelper.GenerateEncryptionKey()
	if err != nil {
		log.Printf("암호화 키 생성 실패: %v", err)
		return
	}

	fmt.Println("새 암호화 키가 생성되었습니다.")
	fmt.Println("이 키를 안전한 곳에 보관하고 환경 변수 TOKEN_ENCRYPTION_KEY에 설정하세요:")
	fmt.Println(key)
	fmt.Println("\n주의: 키를 변경하면 기존에 암호화된 토큰은 더 이상 사용할 수 없습니다.")
}

// 토큰 관련 에러 처리 함수
func handleTokenError(err error) {
	if err == nil {
		return
	}

	// 리프레시 토큰 만료 에러 확인
	if strings.Contains(err.Error(), "리프레시 토큰이 만료되었습니다") {
		fmt.Println("인증 세션이 만료되었습니다. 다시 로그인해주세요.")
		fmt.Println("메뉴에서 1번 또는 2번을 선택하여 다시 인증해주세요.")
		return
	}

	// 인증되지 않은 사용자
	if strings.Contains(err.Error(), "not authenticated") ||
		strings.Contains(err.Error(), "인증되지 않았습니다") {
		fmt.Println("인증되지 않은 사용자입니다. 먼저 로그인해주세요.")
		fmt.Println("메뉴에서 1번 또는 2번을 선택하여 인증해주세요.")
		return
	}

	// 기타 에러
	log.Printf("오류 발생: %v", err)
}
