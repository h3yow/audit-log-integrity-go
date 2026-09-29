package auditlog

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileLock 是对锁文件的排他 flock，保证同一日志路径跨进程只有一个写句柄。
type fileLock struct {
	f *os.File
}

// acquireLock 在 path.lock 上获取非阻塞排他锁；已被占用时返回 ErrLocked。
func acquireLock(path string) (*fileLock, error) {
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditlog: open lock file: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, fmt.Errorf("auditlog: acquire flock: %w", err)
	}
	return &fileLock{f: lf}, nil
}

func (l *fileLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}
