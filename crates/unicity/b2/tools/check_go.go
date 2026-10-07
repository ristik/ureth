//go:build ignore

// Execute inside an isolated bft-core checkout at 9136c66146e56e1c5dc02c51e810a8df7f6b4fe4.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	bp "github.com/unicitynetwork/bft-core/bridgeprofile"
	"math/big"
	"os"
)

func dec(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func word(n uint64) []byte   { b := make([]byte, 32); binary.BigEndian.PutUint64(b[24:], n); return b }
func padded(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
func output(r *bp.Result) []byte {
	marker := make([]byte, 32)
	copy(marker, []byte("UNICITY_TOKEN_SEMANTICS"))
	out := append(marker, word(0)...)
	out = append(out, word(96)...)
	if r == nil {
		out = append(out, make([]byte, 288)...)
		out = append(out, word(320)...)
		return append(out, word(0)...)
	}
	out[63] = 1
	out = append(out, r.Cfg[:]...)
	out = append(out, word(r.Nonce)...)
	out = append(out, padded(r.Amount.Bytes())...)
	out = append(out, r.TokenID[:]...)
	out = append(out, r.Salt[:]...)
	out = append(out, r.FirstPredicateHash[:]...)
	out = append(out, r.LockDigest[:]...)
	out = append(out, padded(r.ReleaseTo[:])...)
	out = append(out, r.Nullifier[:]...)
	out = append(out, word(320)...)
	out = append(out, word(uint64(len(r.Leaves)))...)
	for _, l := range r.Leaves {
		out = append(out, l.SID[:]...)
		out = append(out, l.TxHash[:]...)
	}
	return out
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: check_go.go rust-vectors.json")
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var m struct {
		Oracle  string `json:"oracle"`
		Vectors []struct {
			ID        string `json:"id"`
			Operation int    `json:"operation"`
			Cfg       string `json:"cfg"`
			Payload   string `json:"payload"`
			Request   string `json:"request"`
			Output    string `json:"output"`
			Reason    string `json:"reason"`
			Gas       uint64 `json:"gas"`
		} `json:"vectors"`
	}
	if e = json.Unmarshal(raw, &m); e != nil {
		panic(e)
	}
	if m.Oracle != "9136c66146e56e1c5dc02c51e810a8df7f6b4fe4" {
		panic("wrong oracle pin")
	}
	for _, v := range m.Vectors {
		cfg, e := bp.DecodeCfg(dec(v.Cfg))
		if e != nil {
			panic(e)
		}
		payload := dec(v.Payload)
		var r *bp.Result
		switch v.Operation {
		case 0:
			// The independent generator emits [nonce, amount, predicate]. Decode the
			// first two literal heads here independently of the native implementation.
			pos := 1
			read := func(major byte) uint64 {
				ib := payload[pos]
				pos++
				if ib>>5 != major {
					panic("payload shape")
				}
				ai := ib & 31
				if ai < 24 {
					return uint64(ai)
				}
				n := 1 << uint(ai-24)
				var value uint64
				for i := 0; i < n; i++ {
					value = value<<8 | uint64(payload[pos])
					pos++
				}
				return value
			}
			n := read(0)
			size := read(2)
			amt := new(big.Int).SetBytes(payload[pos : pos+int(size)])
			pos += int(size)
			r, e = bp.PrepareLock(cfg, n, amt, payload[pos:])
		case 1:
			r, e = bp.VerifyMint(cfg, payload)
		case 2:
			r, e = bp.VerifyReturn(cfg, payload)
		default:
			panic("bad op")
		}
		reason, family := bp.Reason(e)
		if reason != v.Reason {
			panic(fmt.Sprintf("%s reason Go=%s native=%s", v.ID, reason, v.Reason))
		}
		if e == nil || family == "invalid" {
			if e != nil {
				r = nil
			}
			want := output(r)
			if !bytes.Equal(want, dec(v.Output)) {
				panic(fmt.Sprintf("%s output mismatch", v.ID))
			}
			leaves := uint64(0)
			// The charge follows decoded history cardinality even when relation false.
			if v.Operation != 0 {
				h, err := bp.DecodeHistory(payload)
				if err != nil {
					panic(err)
				}
				leaves = uint64(len(h.Transfers) + 1)
			}
			gas := 26000 + 16*uint64(len(dec(v.Request))) + 13000*leaves
			if gas != v.Gas {
				panic(fmt.Sprintf("%s gas Go=%d native=%d", v.ID, gas, v.Gas))
			}
		} else if v.Output != "" || v.Gas != 0 {
			panic(fmt.Sprintf("%s expected exceptional failure", v.ID))
		}
	}
	fmt.Printf("PASS: pinned Go verified %d independently constructed Rust vectors (exact reasons, ABI bytes, gas)\n", len(m.Vectors))
}
