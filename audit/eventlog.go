package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// appendEventLog 把清理 / 归档这类管理事件追加到 events.log。
// 该文件只用于可追溯（“什么时候、依据什么移动了链条边界”），
// 不参与记录哈希链的正确性校验。
func appendEventLog(dir string, event map[string]any) error {
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(dir, "events.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

// writeArchiveFile 把一段记录前缀写成自包含的归档文件，
// 归档内记录保持原有 seq/prev_hash/self_hash 不变。
func writeArchiveFile(path string, records []*Record, headAnchor string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range records {
		line, err := marshalLine(r)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}
