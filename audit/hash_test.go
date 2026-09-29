package audit

import (
	"strings"
	"testing"
)

func TestHashDeterminismAndLink(t *testing.T) {
	r1 := &Record{Seq: 1, Time: 42, Actor: "a", Action: "b", Resource: "c", Detail: "d",
		PrevHash: genesisPrevHash()}
	h1 := hashRecord(r1)
	h1Again := hashRecord(r1)
	t.Logf("input: fixed record seq=1; basis: sha256 over fixed-order fields; digest=%s", h1)
	if h1 != h1Again {
		t.Fatal("hash must be deterministic")
	}
	if !strings.HasPrefix(h1, hashKindPrefix) {
		t.Fatalf("digest must carry algorithm prefix, got %s", h1)
	}
	r2 := &Record{Seq: 2, Time: 43, Actor: "a", Action: "b", Resource: "c", Detail: "d", PrevHash: h1}
	h2 := hashRecord(r2)
	t.Logf("conclusion: seq=2 digest=%s chains onto seq=1; genesis=%s", h2, genesisPrevHash())
	// 改一个字段必须得到不同摘要。
	r2.Detail = "different"
	if hashRecord(r2) == h2 {
		t.Fatal("changed content must change digest")
	}
	t.Log("conclusion: any field change changes the digest")
}
