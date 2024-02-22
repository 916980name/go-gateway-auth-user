package ratelimiter

import (
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"
)

func TestLimit(t *testing.T) {
	rl := NewRateLimiter(10, 3, 1)

	// Simulate 100 requests
	var pass, block int
	for i := 0; i < 20; i++ {
		if rl.Acquire(1) {
			pass++
			// t.Logf("Request granted")
		} else {
			block++
			// t.Logf("Request denied")
		}
	}
	if pass != 10 {
		t.Errorf("should pass %q", pass)
	}
	if block != 10 {
		t.Errorf("should block %q", block)
	}
	time.Sleep(3 * time.Second)
	if !rl.Acquire(1) {
		t.Errorf("should PASS")
	}
	if rl.Acquire(1) {
		t.Errorf("should BLOCK")
	}
}

func TestTimeDurationDivideRatio(t *testing.T) {
	d1 := time.Duration(1 * time.Second)
	d2 := time.Duration(3 * time.Second)

	got := float32(d1) / float32(d2)
	f64, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", got), 64)
	got = float32(f64)
	// want := 2

	t.Logf("get:%v", got)
	// if got != want {
	// t.Errorf("got %q, wanted %q", got, want)
	// }
}

func TestFloatCouldOverflow(t *testing.T) {
	currentTokens := math.MaxFloat32
	t.Logf("float32: %f", currentTokens)

	plusOne := currentTokens + 1
	t.Logf("float32 +1: %f", plusOne)

	multiOne := currentTokens * 10000
	t.Logf("float32 *10000: %f", multiOne)

	powSelf := currentTokens * currentTokens * currentTokens * currentTokens * currentTokens
	t.Logf("float32 **5: %f", powSelf)
	if powSelf > 1000 {
		t.Logf("float32 powSelf **5 > 1000")
	}

	powOne := math.Pow(currentTokens, 10) //+Inf
	t.Logf("float32 ^10: %f", powOne)
	if powOne > 1000 {
		t.Logf("float32 ^10 > 1000")
	}

	sqrtOne := math.Sqrt(-10) // NaN
	t.Logf("float32 sqrt-10: %f", sqrtOne)
	if sqrtOne < 1000 {
		t.Logf("float32 sqrt-10 < 1000")
	}
}
