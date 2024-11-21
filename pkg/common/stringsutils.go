package common

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"runtime"
)

func StringArrayOpt(sa []string, operation func(string) string) {
	for i, v := range sa {
		sa[i] = operation(v)
	}
}

func StringToMD5Base64(origin string) string {
	md5bytes := md5.Sum([]byte(origin))
	return base64.StdEncoding.EncodeToString(md5bytes[:])
}

func GetGoroutineID() int {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	var id int
	fmt.Sscanf(string(b), "goroutine %d ", &id)
	return id
}
