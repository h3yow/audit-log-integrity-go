package auditlog

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ChainReport 是对整段日志（当前段）的校验结论。
type ChainReport struct {
	OK            bool     // 全段自洽
	Count         int      // record 帧数量（不含 anchor/genesis）
	LastOffset    int64    // 末帧结束偏移（= 正常收尾应有的文件长度）
	LastSeq       int64    // 末条 record 的全链序号
	LastHash      [32]byte // 末帧链哈希
	FirstIsAnchor bool     // 文件首帧是清理锚点而非 genesis
	TotalRemoved  int64    // 首个 anchor 声明的累计清理数
	Frames        []*Frame // 全部帧（校验/清理共用）
}

var zeroHash [32]byte

// verifyChain 从文件首字节开始做全量结构与哈希链校验。
//
// 判定规则：
//  1. 首帧必须是 genesis（建链）或 anchor（清理后续写）；
//  2. 每一帧的自哈希必须与其内容一致（帧内任一字节被改写即失败）；
//  3. 每个 record 帧头部的 prev 必须等于“文件内前一帧”的链哈希
//     （删除/插入/重排都会让某处 prev 对不上）；
//  4. record 全链序号必须连续：genesis 段从 1 起；anchor 段从
//     anchor.Removed+1 起（重复占位或断号即失败）。
func verifyChain(f *os.File, fileEnd int64) (*ChainReport, *IntegrityProblem) {
	rep := &ChainReport{LastOffset: 0}
	if fileEnd == 0 {
		// 空文件：交由上层决定是否建链，不视为损坏。
		return rep, nil
	}
	sc := newFrameScanner(f, 0, fileEnd)

	var (
		prevHash     [32]byte
		linkOverride [32]byte // 非零表示“下一帧 record 的 prev 必须是它”（清理锚点跨接）
		expectedSeq  int64    = 1
		frameOrd     int
	)
	for {
		res, err := sc.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errTornTail) {
				return nil, &IntegrityProblem{
					Kind:   ErrUncleanShutdown,
					Offset: sc.pos,
					Index:  frameOrd,
					Reason: "trailing bytes form only a partial frame: last append did not finish",
				}
			}
			var prob *IntegrityProblem
			if errors.As(err, &prob) {
				if prob.Index < 0 {
					prob.Index = frameOrd
				}
				return nil, prob
			}
			return nil, &IntegrityProblem{
				Kind:   ErrInvalidFormat,
				Offset: sc.pos,
				Index:  frameOrd,
				Reason: err.Error(),
			}
		}
		fr := res.frame

		switch {
		case frameOrd == 0 && fr.Kind == kindGenesis:
			// 建链帧：其 prev 概念上为零哈希，不做前帧比对。
		case frameOrd == 0 && fr.Kind == kindAnchor:
			if fr.Removed < 1 || fr.UpToSeq != fr.Removed {
				return nil, &IntegrityProblem{
					Kind:   ErrChainBroken,
					Offset: fr.Offset,
					Index:  0,
					Reason: fmt.Sprintf("anchor invariant broken: removed=%d uptoseq=%d", fr.Removed, fr.UpToSeq),
				}
			}
			if fr.Link != fr.Prev {
				return nil, &IntegrityProblem{
					Kind:   ErrChainBroken,
					Offset: fr.Offset,
					Index:  0,
					Reason: "anchor link must equal prev (both bind to the last purged frame)",
				}
			}
			rep.FirstIsAnchor = true
			rep.TotalRemoved = fr.Removed
			expectedSeq = fr.Removed + 1
			// 锚点后第一条 record 必须挂在 Link（=被删末帧哈希）上。
			linkOverride = fr.Link
		case frameOrd > 0 && fr.Kind == kindRecord:
			wantPrev := prevHash
			viaAnchor := false
			if linkOverride != zeroHash {
				wantPrev = linkOverride
				linkOverride = zeroHash
				viaAnchor = true
			}
			if fr.Prev != wantPrev {
				basis := "previous frame hash"
				if viaAnchor {
					basis = "the purge anchor link (last purged frame hash)"
				}
				return nil, &IntegrityProblem{
					Kind:   ErrChainBroken,
					Offset: fr.Offset,
					Index:  frameOrd,
					Reason: fmt.Sprintf("prev-link mismatch at seq=%d: header.prev does not equal %s (a record was altered, deleted or inserted)",
						fr.Seq, basis),
				}
			}
			if fr.Seq != expectedSeq {
				return nil, &IntegrityProblem{
					Kind:   ErrChainBroken,
					Offset: fr.Offset,
					Index:  frameOrd,
					Reason: fmt.Sprintf("seq discontinuity at ordinal %d: got seq=%d want seq=%d (position reused or chain gap)", frameOrd, fr.Seq, expectedSeq),
				}
			}
			expectedSeq++
		default:
			return nil, &IntegrityProblem{
				Kind:   ErrInvalidFormat,
				Offset: fr.Offset,
				Index:  frameOrd,
				Reason: fmt.Sprintf("unexpected frame kind %d at ordinal %d", fr.Kind, frameOrd),
			}
		}

		rep.Frames = append(rep.Frames, fr)
		prevHash = fr.Hash
		rep.LastHash = fr.Hash
		rep.LastOffset = res.end
		if fr.Kind == kindRecord {
			rep.Count++
			rep.LastSeq = fr.Seq
		}
		frameOrd++
	}

	// 末帧哈希若来自 anchor 也无妨；record 序号连续性已在上面逐帧保证。
	if !rep.FirstIsAnchor && frameOrd < 1 {
		return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: 0, Index: -1, Reason: "non-empty file contains no frame"}
	}
	rep.OK = true
	return rep, nil
}

// VerifyArchive 校验一个归档文件：其线格式为“被清理的若干 record 帧 +
// 收尾 anchor 帧”。record 段内 prev 链与序号必须连续，且最后一条 record
// 的哈希必须等于 anchor.prev（归档与清理后的活动段在锚点处重新咬合）。
func VerifyArchive(path string) (*ChainReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() == 0 {
		return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: 0, Index: -1, Reason: "archive is empty"}
	}
	sc := newFrameScanner(f, 0, fi.Size())
	rep := &ChainReport{}
	var (
		prevHash    [32]byte
		expectedSeq int64 = 1
		ord         int
		sawAnchor   bool
	)
	for {
		res, err := sc.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errTornTail) {
				return nil, &IntegrityProblem{Kind: ErrUncleanShutdown, Offset: sc.pos, Index: ord, Reason: "archive ends with a partial frame"}
			}
			var prob *IntegrityProblem
			if errors.As(err, &prob) {
				return nil, prob
			}
			return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: sc.pos, Index: ord, Reason: err.Error()}
		}
		fr := res.frame
		switch {
		case !sawAnchor && fr.Kind == kindRecord:
			if ord > 0 && fr.Prev != prevHash {
				return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: fr.Offset, Index: ord, Reason: "archive: record prev-link mismatch"}
			}
			if fr.Seq != expectedSeq {
				return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: fr.Offset, Index: ord,
					Reason: fmt.Sprintf("archive: seq discontinuity got=%d want=%d", fr.Seq, expectedSeq)}
			}
			expectedSeq++
			rep.Count++
			rep.LastSeq = fr.Seq
		case fr.Kind == kindAnchor:
			if sawAnchor {
				return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: fr.Offset, Index: ord, Reason: "archive: multiple anchors"}
			}
			if rep.Count == 0 {
				return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: fr.Offset, Index: ord, Reason: "archive: anchor with no records"}
			}
			if fr.Prev != prevHash {
				return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: fr.Offset, Index: ord, Reason: "archive: anchor.prev does not match last archived record hash"}
			}
			if fr.Link != fr.Prev {
				return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: fr.Offset, Index: ord, Reason: "archive: anchor link/prev disagreement"}
			}
			if fr.Removed != fr.UpToSeq || fr.UpToSeq != rep.LastSeq {
				return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: fr.Offset, Index: ord,
					Reason: fmt.Sprintf("archive: anchor bounds removed=%d uptoseq=%d lastseq=%d", fr.Removed, fr.UpToSeq, rep.LastSeq)}
			}
			sawAnchor = true
		default:
			return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: fr.Offset, Index: ord,
				Reason: fmt.Sprintf("archive: unexpected frame kind %d", fr.Kind)}
		}
		rep.Frames = append(rep.Frames, fr)
		prevHash = fr.Hash
		rep.LastHash = fr.Hash
		rep.LastOffset = res.end
		ord++
	}
	if !sawAnchor {
		return nil, &IntegrityProblem{Kind: ErrInvalidFormat, Offset: rep.LastOffset, Index: ord, Reason: "archive has no closing anchor"}
	}
	rep.OK = true
	return rep, nil
}
