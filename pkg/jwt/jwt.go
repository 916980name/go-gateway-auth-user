package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTToken is a struct that holds the JWT token information
type JWTToken struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
}

func InitRSAKeyPair(privateKeyStr string, publicKeyStr string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var err error
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyStr))
	if err != nil {
		return nil, nil, fmt.Errorf("init RSA private key failed: %w", err)
	}
	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyStr))
	if err != nil {
		return nil, nil, fmt.Errorf("init RSA public key failed: %w", err)
	}
	return rsaPrivateKey, rsaPublicKey, nil
}

func GenerateJWTRSA(payload map[string]interface{}, ttl time.Duration, key *rsa.PrivateKey) (string, error) {
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = payload             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func GenerateJWTRSARefreshToken(accessTokenMd5 string, ttl time.Duration, key *rsa.PrivateKey) (string, error) {
	now := time.Now().UTC()

	claims := &JWTRefreshToken{
		Md5: accessTokenMd5,
		Exp: now.Add(ttl),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func VerifyJWTRSA(tokenString string, key *rsa.PublicKey) (interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		// try to get payload for logging
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, err
		}
		return claims["dat"], err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["dat"], nil
}

func VerifyJWTRSARefreshToken(tokenString string, key *rsa.PublicKey) (JWTRefreshToken, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return JWTRefreshToken{}, err
	}
	if !token.Valid {
		return JWTRefreshToken{}, errors.New("invalid token")
	}
	claims, ok := token.Claims.(JWTRefreshToken)
	if !ok {
		return JWTRefreshToken{}, fmt.Errorf("validate: invalid")
	}

	return claims, nil
}

// GenerateJWT generates a JWT token with the given payload and secret
func GenerateJWTHMAC(payload map[string]interface{}, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(payload))
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// VerifyJWT verifies the JWT token signature and returns the payload
func VerifyJWTHMAC(tokenString string, secret string) (map[string]interface{}, error) {
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

	tokenString, err := GenerateJWTHMAC(payload, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated JWT token:", tokenString)

	verifiedPayload, err := VerifyJWTHMAC(tokenString, secret)
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
