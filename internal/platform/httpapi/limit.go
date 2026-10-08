package httpapi

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	at     time.Time
}
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

func NewLimiter() *Limiter { return &Limiter{buckets: map[string]bucket{}} }
func (l *Limiter) Allow(key string, rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= 4096 {
			for k, v := range l.buckets {
				if now.Sub(v.at) > 5*time.Minute {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= 4096 {
				return false
			}
		}
		b = bucket{burst, now}
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
	}
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	ok := b.tokens >= 1
	if ok {
		b.tokens--
	}
	l.buckets[key] = b
	return ok
}
