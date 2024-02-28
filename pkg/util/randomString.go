package util

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomString(length int) (string, error) {
	// Calculate the number of bytes needed to represent the desired string length
	byteLength := (length * 6) / 8

	// Generate random bytes
	randomBytes := make([]byte, byteLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Encode random bytes into a base64 string
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Truncate the string to the desired length
	randomString = randomString[:length]

	return randomString, nil
}
