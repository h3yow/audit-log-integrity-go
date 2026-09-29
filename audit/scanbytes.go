package audit

import "bytes"

// scanBytes 是 scanFile 的内存版本，用于校验重写后的日志缓冲。
func scanBytes(b []byte) (lines [][]byte, dangling []byte, size int64) {
	size = int64(len(b))
	if len(b) == 0 {
		return nil, nil, 0
	}
	if b[len(b)-1] != '\n' {
		idx := bytes.LastIndexByte(b, '\n')
		if idx < 0 {
			return nil, b, size
		}
		dangling = b[idx+1:]
		b = b[:idx+1]
	}
	if len(b) > 0 {
		lines = bytes.Split(b[:len(b)-1], []byte{'\n'})
	}
	return lines, dangling, size
}
