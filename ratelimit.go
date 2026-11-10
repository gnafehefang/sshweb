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
