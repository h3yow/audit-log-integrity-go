package auditlog

import (
	"errors"
	"io"
)

var errTornTail = errors.New("auditlog: torn frame at tail")

// scanResult 是扫描器吐出的一帧。
type scanResult struct {
	frame *Frame
	end   int64 // 该帧结束后的文件偏移
}

// readChunkSize 是扫描器每次读入的块大小。
const readChunkSize = 64 << 10

// frameScanner 顺序读取日志文件，逐帧产出结构解析结果。
//
// 它只做“结构层”解析（魔数、长度、帧自哈希），不做帧间链关联判断；
// 链关联由 verify 层完成。读到恰好帧边界上的 EOF 时干净结束。
type frameScanner struct {
	r   io.ReaderAt
	pos int64
	end int64
	buf []byte
}

// newFrameScanner 在 [start, fileEnd) 区间上构造扫描器。
func newFrameScanner(r io.ReaderAt, start, fileEnd int64) *frameScanner {
	return &frameScanner{r: r, pos: start, end: fileEnd}
}

// next 返回下一帧；干净结束时返回 io.EOF；
// 尾部只有半个帧时返回 errTornTail；帧内容与其自哈希不符时返回 *IntegrityProblem。
func (s *frameScanner) next() (*scanResult, error) {
	if s.pos >= s.end {
		return nil, io.EOF
	}
	// 至少读出能容纳长度字段的字节；帧过长时按需继续扩大缓冲。
	if err := s.fill(len(magic) + 1 + 4); err != nil {
		return nil, err
	}
	headerLen := int(uint32(s.buf[offHeaderLen])<<24 | uint32(s.buf[offHeaderLen+1])<<16 |
		uint32(s.buf[offHeaderLen+2])<<8 | uint32(s.buf[offHeaderLen+3]))
	bodyLenOff := offHeader + headerLen
	if err := s.fill(bodyLenOff + 4); err != nil {
		return nil, err
	}
	bodyLen := int(uint32(s.buf[bodyLenOff])<<24 | uint32(s.buf[bodyLenOff+1])<<16 |
		uint32(s.buf[bodyLenOff+2])<<8 | uint32(s.buf[bodyLenOff+3]))
	total := bodyLenOff + 4 + bodyLen + hashSize
	if err := s.fill(total); err != nil {
		return nil, err
	}
	fr, n, err := parseFrame(s.buf[:total], s.pos)
	if err != nil {
		return nil, err
	}
	s.pos += int64(n)
	s.buf = s.buf[n:]
	return &scanResult{frame: fr, end: s.pos}, nil
}

// fill 确保缓冲区至少有 n 个字节可供当前帧解析；
// 只有当文件剩余数据不足 n 个字节时，才判定为 torn tail。
func (s *frameScanner) fill(n int) error {
	for len(s.buf) < n {
		remaining := s.end - (s.pos + int64(len(s.buf)))
		if remaining <= 0 {
			// 数据在帧边界之外结束 => 半个帧。
			if s.pos+int64(len(s.buf)) == s.end && len(s.buf) == 0 {
				return io.EOF
			}
			return errTornTail
		}
		want := int64(readChunkSize)
		if want > remaining {
			want = remaining
		}
		if int64(n-len(s.buf)) > want {
			want = int64(n - len(s.buf))
		}
		tmp := make([]byte, len(s.buf)+int(want))
		copy(tmp, s.buf)
		readAt := s.pos + int64(len(s.buf))
		rn, err := s.r.ReadAt(tmp[len(s.buf):], readAt)
		s.buf = tmp[:len(s.buf)+rn]
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if rn == 0 {
			break
		}
	}
	if len(s.buf) < n {
		return errTornTail
	}
	return nil
}
