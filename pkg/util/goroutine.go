package util

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/log"
	"runtime/debug"
)

func SafeGo(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				stackTrace := string(debug.Stack())
				log.Errorw("Recovered from panic", "panic", r, "stackTrace", stackTrace)
				if common.FLAG_DEBUG {
					debug.PrintStack()
				}
			}
		}()
		fn()
	}()
}
