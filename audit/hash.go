package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// hashKindPrefix 标明哈希算法，便于未来演进时区分。
	hashKindPrefix = "sha256:"
	// genesisHashHex 是链首（seq=1）记录的前驱哈希：对固定串求 SHA-256。
	// 即 sha256("audit-log-genesis-v1")。
	genesisHashHex = hashKindPrefix + "9d0a5ec411cd8aa94b8e51def2d69e650770099ebdc4d716bc826bf55f1428f8"
)

// hashRecord 计算记录的自身哈希。
//
// 哈希输入是字段顺序固定的一行：
//
//	seq|time|actor|action|resource|detail|prev_hash
//
// 不包含 self_hash 自身，字段用 '\x1f'（单元分隔符）连接，
// 从而记录内容（含字段内的 '|'、换行以外的任意字节）都不会造成歧义。
func hashRecord(r *Record) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x1f%d\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s",
		r.Seq, r.Time, r.Actor, r.Action, r.Resource, r.Detail, r.PrevHash)
	return hashKindPrefix + hex.EncodeToString(h.Sum(nil))
}

// genesisPrevHash 返回链首记录使用的前驱哈希。
func genesisPrevHash() string {
	return genesisHashHex
}
