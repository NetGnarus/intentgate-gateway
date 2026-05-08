package budget

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore is a multi-replica-safe Store backed by Redis. Counters
// are atomic across all gateway replicas because INCR is a single
// server-side operation; the EXPIRE call sets the per-key TTL on
// first use.
//
// Connection lifecycle is the caller's responsibility: NewRedisStore
// just wraps the supplied *redis.Client. Pass it nil to disable Redis.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore wraps a *redis.Client. The caller is expected to have
// already validated the connection (e.g. with client.Ping) before
// constructing the store, so failures here surface as runtime errors
// from Increment rather than at construction time.
func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

// Increment satisfies Store.
//
// The implementation runs INCR followed by EXPIRE in a pipeline. EXPIRE
// is set unconditionally on every call which is mildly wasteful but
// avoids a race where a key gets created without a TTL and lingers
// forever. Redis treats EXPIRE on an existing key as an update, not a
// reset of the count, which is the behavior we want.
func (r *RedisStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client is nil")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}
	return incrCmd.Val(), nil
}
