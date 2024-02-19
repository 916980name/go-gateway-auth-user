package jwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTToken is a struct that holds the JWT token information
type JWTToken struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
}

// GenerateJWT generates a JWT token with the given payload and secret
func GenerateJWT(payload map[string]interface{}, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(payload))
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// VerifyJWT verifies the JWT token signature and returns the payload
func VerifyJWT(tokenString string, secret string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims.(jwt.MapClaims), nil
}

/*
func customKeyFunc(token *jwt.Token) (interface{}, error) {
	fmt.Sprintln(token)
	return nil, nil
}

// RetrieveDataFromJWT retrieves the data from the JWT token
func RetrieveDataFromJWT(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, customKeyFunc, jwt.WithValidMethods([]string{"HS512"}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims.(jwt.MapClaims), nil
}
*/

func RunJWTDemo() {
	// Example usage
	payload := map[string]interface{}{
		"user_id": 123,
		"name":    "John Doe",
		"admin":   true,
	}
	secret := "mysecret"

	tokenString, err := GenerateJWT(payload, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated JWT token:", tokenString)

	verifiedPayload, err := VerifyJWT(tokenString, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified JWT payload:", verifiedPayload)

	/*
	retrievedPayload, err := RetrieveDataFromJWT(tokenString)
	if err != nil {
		panic(err)
	}

	fmt.Println("Retrieved JWT payload:", retrievedPayload)
	*/
}
