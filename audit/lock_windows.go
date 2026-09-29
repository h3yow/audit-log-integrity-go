//go:build windows

package audit

import (
	"os"
	"path/filepath"
)

// Windows 下没有 flock，使用独占创建 lock 文件作为粗粒度互斥
// （本项目的主要验证平台是类 Unix）。
type fileLock struct {
	path string
	f    *os.File
}

func acquireLock(dir string) (*fileLock, error) {
	path := filepath.Join(dir, "lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, ErrLogLocked
		}
		return nil, err
	}
	return &fileLock{path: path, f: f}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	_ = os.Remove(l.path)
	return err
}
