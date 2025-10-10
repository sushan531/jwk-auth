package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sushan531/jwk-auth/internal/config"
	"github.com/sushan531/jwk-auth/internal/database"
	"github.com/sushan531/jwk-auth/internal/manager"
	"github.com/sushan531/jwk-auth/internal/repository"
	"github.com/sushan531/jwk-auth/model"
	"github.com/sushan531/jwk-auth/service"
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Interactive menu for JWT operations",
	Run:   runMenu,
}

func init() {
	rootCmd.AddCommand(menuCmd)
}

func runMenu(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database connection
	db, err := database.NewConnection(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create tables if they don't exist
	if err := database.CreateTables(db); err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	// Initialize repository
	userRepo := repository.NewUserAuthRepository(db)

	// Initialize JWK manager with database support
	jwkManager := manager.NewJwkManager(userRepo)

	fmt.Println("Session-based JWT Authentication System initialized")

	var jwtManager = manager.NewJwtManager(jwkManager)
	var authService = service.NewAuthService(jwtManager, jwkManager)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\n=== Session-Based JWT Authentication Menu ===")
		fmt.Println("1. Login (Create Session Key + Generate Tokens)")
		fmt.Println("2. Logout (Delete Session Key)")
		fmt.Println("3. View Active Sessions")
		fmt.Println("4. Verify Access Token")
		fmt.Println("5. Refresh Tokens")
		fmt.Println("6. Logout from All Devices")
		fmt.Println("7. Get User Public Keys")
		fmt.Println("8. Exit")
		fmt.Print("\nSelect an option: ")

		choice, errReadingInput := reader.ReadString('\n')
		if errReadingInput != nil {
			fmt.Printf("Failed to read input: %v\n", errReadingInput)
			continue
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			loginInteractive(jwkManager, authService, reader)
		case "2":
			logoutInteractive(jwkManager, reader)
		case "3":
			viewActiveSessionsInteractive(jwkManager, reader)
		case "4":
			verifyTokenInteractive(authService, reader)
		case "5":
			refreshTokensInteractive(authService, reader)
		case "6":
			logoutAllDevicesInteractive(jwkManager, reader)
		case "7":
			getUserPublicKeysInteractive(jwkManager, reader)
		case "8":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid option, please try again")
		}
	}
}

// loginInteractive simulates user login by creating a session key and generating tokens
func loginInteractive(jwkManager manager.JwkManager, authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userIdStr, _ := reader.ReadString('\n')
	userID, err := strconv.Atoi(strings.TrimSpace(userIdStr))
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter device type (web/android/ios): ")
	deviceType, _ := reader.ReadString('\n')
	deviceType = strings.TrimSpace(deviceType)
	if deviceType == "" {
		deviceType = "web"
	}

	// Load existing keys for user
	jwkManager.LoadUserKeysFromDB(userID)

	// Create session key
	keyID, err := jwkManager.CreateSessionKey(userID, deviceType)
	if err != nil {
		fmt.Printf("Error creating session key: %v\n", err)
		return
	}

	fmt.Printf("✓ Session key created: %s\n", keyID)

	// Generate token pair using the session key
	user := &model.User{Id: userID, Username: username}
	tokenPair, err := authService.GenerateTokenPairWithKeyID(user, keyID)
	if err != nil {
		fmt.Printf("Error generating tokens: %v\n", err)
		return
	}

	fmt.Printf("✓ Login successful!\n")
	fmt.Printf("Access Token: %s\n", tokenPair.AccessToken)
	fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
	fmt.Printf("Device: %s\n", deviceType)
	fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn)
}

// logoutInteractive removes a specific session key
func logoutInteractive(jwkManager manager.JwkManager, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userIdStr, _ := reader.ReadString('\n')
	userID, err := strconv.Atoi(strings.TrimSpace(userIdStr))
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	// Load user keys first
	jwkManager.LoadUserKeysFromDB(userID)

	// Show active sessions
	sessions, err := jwkManager.GetSessionKeys(userID)
	if err != nil || len(sessions) == 0 {
		fmt.Println("No active sessions found")
		return
	}

	fmt.Println("Active sessions:")
	for i, keyID := range sessions {
		fmt.Printf("%d. %s\n", i+1, keyID)
	}

	fmt.Print("Enter session number to logout: ")
	sessionNumStr, _ := reader.ReadString('\n')
	sessionNum, err := strconv.Atoi(strings.TrimSpace(sessionNumStr))
	if err != nil || sessionNum < 1 || sessionNum > len(sessions) {
		fmt.Println("Invalid session number")
		return
	}

	keyID := sessions[sessionNum-1]
	err = jwkManager.DeleteSessionKey(userID, keyID)
	if err != nil {
		fmt.Printf("Error logging out: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully logged out from session: %s\n", keyID)
}

// viewActiveSessionsInteractive shows all active sessions for a user
func viewActiveSessionsInteractive(jwkManager manager.JwkManager, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userIdStr, _ := reader.ReadString('\n')
	userID, err := strconv.Atoi(strings.TrimSpace(userIdStr))
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	// Load user keys from database
	jwkManager.LoadUserKeysFromDB(userID)

	sessions, err := jwkManager.GetSessionKeys(userID)
	if err != nil {
		fmt.Printf("Error getting sessions: %v\n", err)
		return
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions found")
		return
	}

	fmt.Printf("Active sessions for user %d:\n", userID)
	for i, keyID := range sessions {
		fmt.Printf("%d. %s\n", i+1, keyID)
	}
}

// logoutAllDevicesInteractive removes all session keys for a user
func logoutAllDevicesInteractive(jwkManager manager.JwkManager, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userIdStr, _ := reader.ReadString('\n')
	userID, err := strconv.Atoi(strings.TrimSpace(userIdStr))
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	// Load user keys first
	jwkManager.LoadUserKeysFromDB(userID)

	sessions, err := jwkManager.GetSessionKeys(userID)
	if err != nil || len(sessions) == 0 {
		fmt.Println("No active sessions found")
		return
	}

	fmt.Printf("This will logout from %d active sessions. Continue? (y/N): ", len(sessions))
	confirm, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("Cancelled")
		return
	}

	// Delete all sessions
	for _, keyID := range sessions {
		jwkManager.DeleteSessionKey(userID, keyID)
	}

	fmt.Printf("✓ Successfully logged out from all devices (%d sessions)\n", len(sessions))
}

// getUserPublicKeysInteractive shows all public keys for a user
func getUserPublicKeysInteractive(jwkManager manager.JwkManager, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userIdStr, _ := reader.ReadString('\n')
	userID, err := strconv.Atoi(strings.TrimSpace(userIdStr))
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	// Load user keys from database
	jwkManager.LoadUserKeysFromDB(userID)

	publicKeys, err := jwkManager.GetUserPublicKeys(userID)
	if err != nil {
		fmt.Printf("Error getting public keys: %v\n", err)
		return
	}

	if len(publicKeys) == 0 {
		fmt.Println("No public keys found for user")
		return
	}

	fmt.Printf("Public keys for user %d:\n", userID)
	for i, key := range publicKeys {
		fmt.Printf("%d. RSA-%d key\n", i+1, key.Size()*8)
	}
}

func refreshTokensInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter refresh token: ")
	refreshToken, _ := reader.ReadString('\n')
	refreshToken = strings.TrimSpace(refreshToken)

	fmt.Print("Enter username for new access token: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Extract key ID from the refresh token
	keyID, err := authService.ExtractKeyIDFromToken(refreshToken)
	if err != nil {
		fmt.Printf("Error extracting key ID from token: %v\n", err)
		return
	}

	tokenPair, err := authService.RefreshTokensWithKeyID(refreshToken, username, keyID)
	if err != nil {
		fmt.Printf("Error refreshing tokens: %v\n", err)
		return
	}

	fmt.Printf("\nNew Access Token: %s\n", tokenPair.AccessToken)
	fmt.Printf("New Refresh Token: %s\n", tokenPair.RefreshToken)
	fmt.Printf("Token Type: %s\n", tokenPair.TokenType)
	fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn)
}

func verifyTokenInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter access token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	user, err := authService.VerifyToken(token)
	if err != nil {
		fmt.Printf("Error verifying token: %v\n", err)
		return
	}

	fmt.Printf("\nToken is valid! User: %+v\n", user)
}

func verifyRefreshTokenInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter refresh token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	user, err := authService.VerifyRefreshToken(token)
	if err != nil {
		fmt.Printf("Error verifying refresh token: %v\n", err)
		return
	}

	fmt.Printf("\nRefresh token is valid! User: %+v\n", user)
}
