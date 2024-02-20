package ratelimiter

import (
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
	f64, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", got), 64)
	ratio := float32(f64)
	rl.lastRefillTime = refillTime

	currentTokens := ratio*float32(rl.refillAmount) + float32(rl.currentTokens) - float32(number)
	// fmt.Printf("token: %f\n", currentTokens)

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
