package util

import (
	"crypto/rand"
	"encoding/base64"
	"time"
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

func ToMilliSec(t time.Time) int64 {
	return t.UnixNano() / 1000000
}

func FromMilliSec(m int64) time.Time {
	seconds := m / 1000
	nanoseconds := (m % 1000) * 1000000
	return time.Unix(seconds, nanoseconds)
}

func ParseTime(ts string) (time.Time, error) {
	layout := "2006-01-02T15:04:05Z"
	return time.Parse(layout, ts)
}
