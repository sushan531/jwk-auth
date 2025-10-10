package cmd

import (
	"bufio"
	"encoding/json"
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

	// Try to load existing key set from database, otherwise create new one
	if err := jwkManager.LoadJwkSetFromDB(); err != nil {
		fmt.Printf("No existing key set found, creating new one: %v\n", err)
		if err := jwkManager.InitializeJwkSet(2); err != nil {
			fmt.Printf("Error initializing JWK set: %v\n", err)
			return
		}
		// Save the new key set to database with a default user ID (0 for system)
		if err := jwkManager.SaveJwkSetToDB(0); err != nil {
			fmt.Printf("Error saving JWK set to database: %v\n", err)
			return
		}
		fmt.Println("New key set created and saved to database")
	} else {
		fmt.Println("Loaded existing key set from database")
	}

	var jwtManager = manager.NewJwtManager(jwkManager)
	var authService = service.NewAuthService(jwtManager, jwkManager)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nJWT Authentication Menu:")
		fmt.Println("1. Generate Token (Legacy)")
		fmt.Println("2. Generate Token Pair (Access + Refresh)")
		fmt.Println("3. Refresh Tokens")
		fmt.Println("4. Get JWKS")
		fmt.Println("5. Verify Access Token")
		fmt.Println("6. Verify Refresh Token")
		fmt.Println("7. Regenerate Key Set")
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
			generateTokenInteractive(authService, reader)
		case "2":
			generateTokenPairInteractive(authService, reader)
		case "3":
			refreshTokensInteractive(authService, reader)
		case "4":
			getJWKSInteractive(authService)
		case "5":
			verifyTokenInteractive(authService, reader)
		case "6":
			verifyRefreshTokenInteractive(authService, reader)
		case "7":
			regenerateKeySetInteractive(jwkManager, reader)
		case "8":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid option, please try again")
		}
	}
}

func generateTokenInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userId, errReadingUserIdInput := reader.ReadString('\n')
	if errReadingUserIdInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserIdInput)
		return
	}
	userIdInInt, errParsingString := strconv.Atoi(strings.TrimSpace(userId))
	if errParsingString != nil {
		fmt.Printf("Invalid user ID: %v\n", errParsingString)
		return
	}

	fmt.Print("Enter username: ")
	username, errReadingUserUserNameInput := reader.ReadString('\n')
	if errReadingUserUserNameInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserUserNameInput)
		return
	}

	username = strings.TrimSpace(username)

	user := &model.User{
		Id:       userIdInInt,
		Username: username,
	}

	token, err := authService.GenerateJwt(user)
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("\nGenerated Token: %s\n", token)
}

func getJWKSInteractive(authService service.AuthService) {
	jwks, err := authService.GetPublicKeys()
	if err != nil {
		fmt.Printf("Error getting JWKS: %v\n", err)
		return
	}

	bytes, err := json.Marshal(jwks)
	if err != nil {
		fmt.Printf("Error getting marshalling data: %v\n", err)
		return
	}

	fmt.Printf("\nPublic JWKS: %+v\n", string(bytes))
}

func generateTokenPairInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userId, errReadingUserIdInput := reader.ReadString('\n')
	if errReadingUserIdInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserIdInput)
		return
	}
	userIdInInt, errParsingString := strconv.Atoi(strings.TrimSpace(userId))
	if errParsingString != nil {
		fmt.Printf("Invalid user ID: %v\n", errParsingString)
		return
	}

	fmt.Print("Enter username: ")
	username, errReadingUserUserNameInput := reader.ReadString('\n')
	if errReadingUserUserNameInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserUserNameInput)
		return
	}

	username = strings.TrimSpace(username)

	user := &model.User{
		Id:       userIdInInt,
		Username: username,
	}

	tokenPair, err := authService.GenerateTokenPair(user)
	if err != nil {
		fmt.Printf("Error generating token pair: %v\n", err)
		return
	}

	fmt.Printf("\nAccess Token: %s\n", tokenPair.AccessToken)
	fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
	fmt.Printf("Token Type: %s\n", tokenPair.TokenType)
	fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn)
}

func refreshTokensInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter refresh token: ")
	refreshToken, _ := reader.ReadString('\n')
	refreshToken = strings.TrimSpace(refreshToken)

	fmt.Print("Enter username for new access token: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	tokenPair, err := authService.RefreshTokens(refreshToken, username)
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

func regenerateKeySetInteractive(jwkManager manager.JwkManager, reader *bufio.Reader) {
	fmt.Print("Enter user ID for new key set (0 for system): ")
	userIdStr, _ := reader.ReadString('\n')
	userIdStr = strings.TrimSpace(userIdStr)

	userID, err := strconv.Atoi(userIdStr)
	if err != nil {
		fmt.Printf("Invalid user ID: %v\n", err)
		return
	}

	fmt.Print("Enter number of keys to generate (default 2): ")
	numKeysStr, _ := reader.ReadString('\n')
	numKeysStr = strings.TrimSpace(numKeysStr)

	numKeys := 2
	if numKeysStr != "" {
		if parsed, err := strconv.Atoi(numKeysStr); err == nil {
			numKeys = parsed
		}
	}

	fmt.Printf("Generating new key set with %d keys...\n", numKeys)

	if err := jwkManager.InitializeJwkSet(numKeys); err != nil {
		fmt.Printf("Error generating new key set: %v\n", err)
		return
	}

	if err := jwkManager.SaveJwkSetToDB(userID); err != nil {
		fmt.Printf("Error saving new key set to database: %v\n", err)
		return
	}

	fmt.Printf("New key set generated and saved for user ID %d\n", userID)
	fmt.Println("WARNING: All previously issued tokens will be invalid!")
}
