package dbredis

import (
	"context"
	"file-transfer/pkg/log"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	client     *redis.Client
	clientOnce sync.Once
)

func initClient(ctx context.Context, cs string) error {
	var err error
	opts, err := redis.ParseURL(cs)
	if err != nil {
		return err
	}
	client = redis.NewClient(opts)
	return nil
}

func GetClient(ctx context.Context, cs string) *redis.Client {
	clientOnce.Do(func() {
		if client == nil {
			if ctx == nil {
				_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
			}
			initClient(ctx, cs)
		}
	})
	return client
}

func CloseClient(ctx context.Context) error {
	if client != nil {
		err := client.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func RetryConnect(ctx context.Context, retryDelay time.Duration, cs string) error {
	var err error
	for {
		err = initClient(ctx, cs)
		if err == nil {
			return nil
		}
		log.Errorw("Failed to connect to redis (" + err.Error() + "). Retrying in " + retryDelay.String())
		time.Sleep(retryDelay)
	}
}

func IsErrNotFound(err error) bool {
	if err != nil && (strings.Contains(err.Error(), "not found in cache") || strings.Contains(err.Error(), "redis: nil")) {
		return true
	} else {
		return false
	}
}
