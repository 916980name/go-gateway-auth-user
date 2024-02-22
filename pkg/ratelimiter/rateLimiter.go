package ratelimiter

import (
	"api-gateway/pkg/common"
	"fmt"
	"strconv"
	"sync"
	"time"
)

type RateLimiter struct {
	maxTokens      int
	refillInterval time.Duration
	refillAmount   int
	lock           sync.Mutex
	lastRefillTime time.Time
	currentTokens  int
}

/*
@params refillInterval unit seconds
*/
func NewRateLimiter(maxTokens int, refillInterval int, refillAmount int) *RateLimiter {
	return &RateLimiter{
		maxTokens:      maxTokens,
		refillInterval: time.Duration(refillInterval * int(time.Second)),
		refillAmount:   refillAmount,
		lastRefillTime: time.Now(),
		currentTokens:  maxTokens,
	}
}

func (rl *RateLimiter) Acquire(number int) bool {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	refillTime := time.Now()
	got := float32(refillTime.Sub(rl.lastRefillTime)) / float32(rl.refillInterval)
	f32, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", got), 32)
	ratio := float32(f32)
	rl.lastRefillTime = refillTime

	// currentTokens(float) could not overflow, int could overflow, math.Pow()/Sqrt() could result not number
	currentTokens := ratio*float32(rl.refillAmount) + float32(rl.currentTokens) - float32(number)
	if common.FLAG_DEBUG {
		fmt.Printf("| | | max: %d, interval: %v, lastrefill: %v, token: %f, Acuire: %d\n",
			rl.maxTokens, rl.refillInterval, rl.lastRefillTime, currentTokens, number)
	}

	if currentTokens > float32(rl.maxTokens) {
		rl.currentTokens = rl.maxTokens
		return true
	} else if currentTokens < 0 {
		rl.currentTokens = 0
		return false
	} else {
		rl.currentTokens = int(currentTokens)
		return true
	}
}
