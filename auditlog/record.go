package auditlog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// frameKind 标识帧的类型。
type frameKind byte

const (
	kindGenesis frameKind = 1 // 建链锚点帧（文件第一个帧）
	kindRecord  frameKind = 2 // 审计记录帧
	kindAnchor  frameKind = 3 // 清理边界锚点帧（清理后文件的第一个帧）
)

// magic 与 version 标识日志文件格式。
const (
	magic       = "AUDLOG1"
	version     = byte(1)
	maxFieldLen = 16 << 20 // 单个 header/body 长度上限，防止损坏长度字段撑爆内存
)

// 帧固定布局（大端）：
//
//	magic(7) kind(1) headerLen(4) headerJSON(headerLen) bodyLen(4) body(bodyLen) hash(32)
//
// hash = SHA256(headerJSON || body)，headerJSON 中带有 prev，
// 因此每帧都与前一帧形成密码学关联。
const (
	offMagic     = 0
	offKind      = 7
	offHeaderLen = 8
	offHeader    = 12
	hashSize     = sha256.Size
)

// Record 是一条由调用方提交的审计记录内容。
type Record struct {
	Timestamp time.Time // 事件时间；为零时由 Store 时钟填充
	Actor     string    // 操作主体
	Action    string    // 操作类型
	Resource  string    // 操作对象
	Detail    string    // 附加载荷（可为空），作为帧 body 参与哈希
}

// recordHeader 是参与哈希计算的记录帧头部（JSON 字段固定，编码确定）。
type recordHeader struct {
	Kind   byte     `json:"kind"`
	Seq    int64    `json:"seq"`  // 全链单调递增序号
	Time   int64    `json:"time"` // 事件时间，Unix 纳秒
	Actor  string   `json:"actor"`
	Action string   `json:"action"`
	Res    string   `json:"resource"`
	NBody  int      `json:"nbody"` // 载荷字节数
	Prev   [32]byte `json:"prev"`  // 前一帧的链哈希（genesis 为全零）
}

// genesisHeader 是建链锚点帧的头部。
type genesisHeader struct {
	Kind byte `json:"kind"`
}

// anchorHeader 是清理边界锚点帧的头部。
type anchorHeader struct {
	Kind     byte     `json:"kind"`
	Removed  int64    `json:"removed"` // 截至该锚点，历史上累计被清理的记录数
	UpToSeq  int64    `json:"uptoseq"` // 被清理前缀中最后一条记录的序号
	UpToTime int64    `json:"uptotime"`
	Prev     [32]byte `json:"prev"` // 被清理前缀最后一条记录帧的哈希（归档咬合证据）
	// Link 是锚点之后第一条 record 的 prev 应有的值。
	// 它等于被删末帧的哈希（与 Prev 相同），使跨锚点的前后衔接可独立校验。
	Link [32]byte `json:"link"`
}

// Frame 是从日志中解析出的一个帧。
type Frame struct {
	Kind    frameKind
	Offset  int64 // 帧在日志文件中的起始偏移
	End     int64 // 帧结束后的偏移
	Seq     int64 // record 帧的全链序号
	Time    time.Time
	Rec     *Record // kindRecord 时非空
	Hash    [32]byte
	Prev    [32]byte
	Link    [32]byte // anchor 帧：其后第一条 record 应挂接的哈希
	Removed int64    // anchor 帧字段
	UpToSeq int64

	headerJSON []byte // 解析时留存，供链校验使用
	body       []byte
}

// frameHash 计算帧的链哈希：SHA256(headerJSON || body)。
func frameHash(headerJSON, body []byte) [32]byte {
	h := sha256.New()
	h.Write(headerJSON)
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func buildFrame(kind byte, header any, body []byte) ([]byte, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("auditlog: encode header: %w", err)
	}
	if len(headerJSON) > maxFieldLen || len(body) > maxFieldLen {
		return nil, errors.New("auditlog: frame too large")
	}
	sum := frameHash(headerJSON, body)
	out := make([]byte, 0, len(magic)+1+4+len(headerJSON)+4+len(body)+hashSize)
	out = append(out, magic...)
	out = append(out, kind)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(headerJSON)))
	out = append(out, lenBuf[:]...)
	out = append(out, headerJSON...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	out = append(out, lenBuf[:]...)
	out = append(out, body...)
	out = append(out, sum[:]...)
	return out, nil
}

// encodeRecordFrame 编码一条审计记录帧。
func encodeRecordFrame(h recordHeader, body []byte) ([]byte, error) {
	h.Kind = byte(kindRecord)
	h.NBody = len(body)
	return buildFrame(h.Kind, h, body)
}

// encodeAnchorFrame 编码一个清理边界锚点帧。
func encodeAnchorFrame(h anchorHeader) ([]byte, error) {
	h.Kind = byte(kindAnchor)
	return buildFrame(h.Kind, h, nil)
}

// encodeGenesisFrame 编码建链锚点帧。
func encodeGenesisFrame() ([]byte, error) {
	return buildFrame(byte(kindGenesis), genesisHeader{Kind: byte(kindGenesis)}, nil)
}

// parseFrame 在 data 的起始位置解析一个帧，返回帧信息与帧总长度。
// data 必须从一帧的边界开始；帧不完整时返回 errTornTail。
func parseFrame(data []byte, offset int64) (*Frame, int, error) {
	if len(data) < len(magic)+1+4 {
		return nil, 0, errTornTail
	}
	if string(data[:len(magic)]) != magic {
		return nil, 0, fmt.Errorf("%w: bad magic at offset %d", ErrInvalidFormat, offset)
	}
	kind := frameKind(data[offKind])
	headerLen := int(binary.BigEndian.Uint32(data[offHeaderLen : offHeaderLen+4]))
	if headerLen > maxFieldLen {
		return nil, 0, fmt.Errorf("%w: header length %d exceeds limit at offset %d", ErrInvalidFormat, headerLen, offset)
	}
	bodyLenOff := offHeader + headerLen
	if len(data) < bodyLenOff+4 {
		return nil, 0, errTornTail
	}
	bodyLen := int(binary.BigEndian.Uint32(data[bodyLenOff : bodyLenOff+4]))
	if bodyLen > maxFieldLen {
		return nil, 0, fmt.Errorf("%w: body length %d exceeds limit at offset %d", ErrInvalidFormat, bodyLen, offset)
	}
	bodyOff := bodyLenOff + 4
	total := bodyOff + bodyLen + hashSize
	if len(data) < total {
		return nil, 0, errTornTail
	}
	headerJSON := data[offHeader:bodyLenOff]
	body := data[bodyOff : bodyOff+bodyLen]
	gotHash := data[bodyOff+bodyLen : total]

	fr := &Frame{Kind: kind, Offset: offset, End: offset + int64(total)}
	fr.headerJSON = append(fr.headerJSON, headerJSON...) // copy: 底层 data 可能被复用
	fr.body = append(fr.body, body...)

	want := frameHash(headerJSON, body)
	if string(gotHash) != string(want[:]) {
		// 帧自身内容与哈希不符：定位为“链断裂”（被改写）。
		return fr, total, &IntegrityProblem{
			Kind:   ErrChainBroken,
			Offset: offset,
			Index:  -1,
			Reason: "frame self-hash mismatch: content or hash was altered",
		}
	}
	fr.Hash = want

	switch kind {
	case kindRecord:
		var h recordHeader
		if err := json.Unmarshal(headerJSON, &h); err != nil {
			return nil, 0, fmt.Errorf("%w: corrupt record header at offset %d: %v", ErrInvalidFormat, offset, err)
		}
		fr.Seq = h.Seq
		fr.Time = time.Unix(0, h.Time).UTC()
		fr.Prev = h.Prev
		if h.NBody != bodyLen {
			return nil, 0, fmt.Errorf("%w: body length mismatch at offset %d", ErrInvalidFormat, offset)
		}
		fr.Rec = &Record{
			Timestamp: fr.Time,
			Actor:     h.Actor,
			Action:    h.Action,
			Resource:  h.Res,
			Detail:    string(body),
		}
	case kindGenesis:
		var h genesisHeader
		if err := json.Unmarshal(headerJSON, &h); err != nil {
			return nil, 0, fmt.Errorf("%w: corrupt genesis header at offset %d", ErrInvalidFormat, offset)
		}
	case kindAnchor:
		var h anchorHeader
		if err := json.Unmarshal(headerJSON, &h); err != nil {
			return nil, 0, fmt.Errorf("%w: corrupt anchor header at offset %d", ErrInvalidFormat, offset)
		}
		fr.Prev = h.Prev
		fr.Link = h.Link
		fr.Removed = h.Removed
		fr.UpToSeq = h.UpToSeq
		if h.UpToTime != 0 {
			fr.Time = time.Unix(0, h.UpToTime).UTC()
		}
	default:
		return nil, 0, fmt.Errorf("%w: unknown frame kind %d at offset %d", ErrInvalidFormat, kind, offset)
	}
	return fr, total, nil
}
