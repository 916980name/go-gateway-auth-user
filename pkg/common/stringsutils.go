package common

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
)

func StringArrayOpt(sa []string, operation func(string) string) {
	for i, v := range sa {
		sa[i] = operation(v)
	}
}

func StringToHashBase64(origin string) string {
	hash := sha256.Sum256([]byte(origin))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func GetGoroutineID() int {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	var id int
	fmt.Sscanf(string(b), "goroutine %d ", &id)
	return id
}
