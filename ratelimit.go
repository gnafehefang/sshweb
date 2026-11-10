package main

// ratelimit.go — 失败计数锁定（登录、探针解锁）与令牌桶限流（公开接口）。
// 所有表都有容量上限，超出时先清理过期项，仍满则拒绝新键（宁可误伤也不无限增长）。

import (
	"sync"
	"time"
)

// ---------------- 失败计数锁定 ----------------

type failState struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
	lockCount   int
}

type failTracker struct {
	mu         sync.Mutex
	m          map[string]*failState
	maxFails   int           // 窗口内允许的失败次数
	window     time.Duration // 计数窗口
	lockFor    time.Duration // 首次锁定时长，之后每次翻倍
	maxLock    time.Duration
	maxEntries int
	now        func() time.Time
}

func newFailTracker(maxFails int, window, lockFor, maxLock time.Duration) *failTracker {
	return &failTracker{
		m: map[string]*failState{}, maxFails: maxFails, window: window,
		lockFor: lockFor, maxLock: maxLock, maxEntries: 50000, now: time.Now,
	}
}

// blocked 返回该键当前是否处于锁定期以及剩余时长
func (f *failTracker) blocked(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.m[key]
	if !ok {
		return false, 0
	}
	now := f.now()
	if now.Before(st.lockedUntil) {
		return true, st.lockedUntil.Sub(now)
	}
	return false, 0
}

func (f *failTracker) fail(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	st, ok := f.m[key]
	if !ok {
		if len(f.m) >= f.maxEntries {
			f.pruneLocked(now)
		}
		st = &failState{first: now}
		f.m[key] = st
	}
	if now.Sub(st.first) > f.window {
		st.fails, st.first = 0, now
	}
	st.fails++
	if st.fails >= f.maxFails {
		d := f.lockFor << uint(min(st.lockCount, 16))
		if d > f.maxLock || d <= 0 {
			d = f.maxLock
		}
		st.lockedUntil = now.Add(d)
		st.lockCount++
		st.fails, st.first = 0, now
	}
}

func (f *failTracker) success(key string) {
	f.mu.Lock()
	delete(f.m, key)
	f.mu.Unlock()
}

func (f *failTracker) pruneLocked(now time.Time) {
	for k, st := range f.m {
		if now.After(st.lockedUntil) && now.Sub(st.first) > f.window {
			delete(f.m, k)
		}
	}
}

// ---------------- 令牌桶（按键） ----------------

type keyedLimiter struct {
	mu         sync.Mutex
	rate       float64 // 每秒补充
	burst      float64
	m          map[string]*bucket
	maxEntries int
	now        func() time.Time
}

func newKeyedLimiter(rate, burst float64, maxEntries int) *keyedLimiter {
	return &keyedLimiter{rate: rate, burst: burst, m: map[string]*bucket{}, maxEntries: maxEntries, now: time.Now}
}

func (l *keyedLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.m[key]
	if !ok {
		if len(l.m) >= l.maxEntries {
			// 清理已经回满的桶；仍满则拒绝（不无限增长）
			for k, v := range l.m {
				if v.tokens+now.Sub(v.last).Seconds()*l.rate >= l.burst {
					delete(l.m, k)
				}
			}
			if len(l.m) >= l.maxEntries {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	b.last = now
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// localBucket 单个连接内使用的令牌桶（调用方保证串行访问）
type localBucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newLocalBucket(rate, burst float64) localBucket {
	return localBucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *localBucket) allow() bool {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	b.last = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
