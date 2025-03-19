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

	var choice int64 = -1

	for {
		fmt.Println("Please choose one of the following options:")
		fmt.Println("0. Exit")
		fmt.Println("1. Device Code Flow 인증 - 다른 기기에서 코드 입력")
		fmt.Println("2. Authorization Code Flow 인증 - 브라우저 자동 열기")
		fmt.Println("3. Display access token")
		fmt.Println("4. List my inbox")
		fmt.Println("5. Send mail")
		fmt.Println("6. Display refresh token")

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
