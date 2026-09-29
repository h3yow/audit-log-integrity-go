//go:build !windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// fileLock 基于 flock(2) 的进程间互斥锁，保证同一数据目录同时只有一个 Store。
type fileLock struct {
	path string
	f    *os.File
}

func acquireLock(dir string) (*fileLock, error) {
	path := filepath.Join(dir, "lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	// 非阻塞抢锁：拿不到立刻得到可区分的错误，而不是挂起。
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrLogLocked, err)
	}
	return &fileLock{path: path, f: f}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err1 := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err2 := l.f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
