package main

import (
	"fmt"
	"graphtutorial/graphhelper"
	"log"
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
		fmt.Println("3. 액세스 토큰 표시")
		fmt.Println("4. 받은 편지함 목록 보기")
		fmt.Println("5. 이메일 보내기")
		fmt.Println("6. 리프레시 토큰 표시")
		fmt.Println("7. DB에서 사용자 토큰 로드")
		fmt.Println("8. 현재 사용자 토큰을 DB에 저장")
		fmt.Println("9. DB에 저장된 사용자 목록 표시")

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
			displayAccessToken(graphHelper)
		case 4:
			listInbox(graphHelper)
		case 5:
			sendMail(graphHelper)
		case 6:
			displayRefreshToken(graphHelper)
		case 7:
			loadUserTokenFromDB(graphHelper)
		case 8:
			saveUserTokenToDB(graphHelper)
		case 9:
			listDBUsers(graphHelper)
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
		log.Panicf("Error getting user: %v\n", err)
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
		log.Panicf("Error getting user token: %v\n", err)
	}

	fmt.Printf("User token: %s\n", *token)
	fmt.Println()
}

func displayRefreshToken(graphHelper *graphhelper.GraphHelper) {
	token, err := graphHelper.GetUserRefreshToken()
	if err != nil {
		log.Panicf("Error getting user refresh token: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("Refresh token: %s\n", *token)
	fmt.Println()
}

func listInbox(graphHelper *graphhelper.GraphHelper) {
	messages, err := graphHelper.GetInbox()
	if err != nil {
		log.Panicf("Error getting user's inbox: %v\n", err)
	}

	location, err := time.LoadLocation("Local")
	if err != nil {
		log.Panicf("Error loading local timezone: %v\n", err)
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
		log.Panicf("Error getting user: %v\n", err)
	}

	email := user.GetMail()
	if email == nil {
		email = user.GetUserPrincipalName()
	}

	subject := "Testing Microsoft Graph"
	body := "Hello world!"
	err = graphHelper.SendMail(&subject, &body, email)
	if err != nil {
		log.Panicf("Error sending mail: %v\n", err)
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
