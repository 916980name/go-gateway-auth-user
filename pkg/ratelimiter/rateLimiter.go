package ratelimiter

import (
	"api-gateway/pkg/common"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

type RateLimiter struct {
	MaxTokens      int
	RefillInterval time.Duration
	RefillAmount   int
	lock           sync.Mutex
	LastRefillTime time.Time
	CurrentTokens  int
}

func (rl RateLimiter) MarshalBinary() (data []byte, err error) {
	obj := make(map[string]interface{})
	obj["maxTokens"] = rl.MaxTokens
	obj["refillInterval"] = rl.RefillInterval
	obj["refillAmount"] = rl.RefillAmount
	obj["lastRefillTime"] = rl.LastRefillTime
	obj["currentTokens"] = rl.CurrentTokens
	return json.Marshal(obj)
}

func UnmarshalRateLimiterString(data string) (*RateLimiter, error) {
	rl := new(RateLimiter)
	err := json.Unmarshal([]byte(data), &rl)
	return rl, err
}

func UnmarshalRateLimiterInterface(limiter interface{}) (*RateLimiter, error) {
	switch l := limiter.(type) {
	case *RateLimiter:
		return l, nil
	case string:
		return UnmarshalRateLimiterString(l)
	}
	return nil, fmt.Errorf("unmarshal limiter failed")
}

/*
@params refillInterval unit seconds
*/
func NewRateLimiter(maxTokens int, refillInterval int, refillAmount int) *RateLimiter {
	return &RateLimiter{
		MaxTokens:      maxTokens,
		RefillInterval: time.Duration(refillInterval * int(time.Second)),
		RefillAmount:   refillAmount,
		LastRefillTime: time.Now(),
		CurrentTokens:  maxTokens,
	}
}

func (rl *RateLimiter) Acquire(number int) bool {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	refillTime := time.Now()
	got := float32(refillTime.Sub(rl.LastRefillTime)) / float32(rl.RefillInterval)
	f32, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", got), 32)
	ratio := float32(f32)
	rl.LastRefillTime = refillTime

	// currentTokens(float) could not overflow, int could overflow, math.Pow()/Sqrt() could result not number
	currentTokens := ratio*float32(rl.RefillAmount) + float32(rl.CurrentTokens) - float32(number)
	if common.FLAG_DEBUG {
		fmt.Printf("| | | max: %d, interval: %v, lastrefill: %v, token: %f, Acuire: %d\n",
			rl.MaxTokens, rl.RefillInterval, rl.LastRefillTime, currentTokens, number)
	}

	if currentTokens > float32(rl.MaxTokens) {
		rl.CurrentTokens = rl.MaxTokens
		return true
	} else if currentTokens < 0 {
		rl.CurrentTokens = 0
		return false
	} else {
		rl.CurrentTokens = int(currentTokens)
		return true
	}
}
