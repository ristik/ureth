//go:build ignore

// Run from a bft-core checkout at the documented immutable oracle pin:
// GOCACHE=/private/tmp/gocache-b1pr2 go run /path/to/check_go.go rust-vectors.json
// This is conformance, not generation or authenticated admission.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1state"
)

func decode(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: check_go.go rust-vectors.json")
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var m b1gen.Manifest
	if e = json.Unmarshal(raw, &m); e != nil {
		panic(e)
	}
	for _, v := range m.Vectors {
		var reg *b1ref.Registry
		if p := v.PreState; p != nil {
			reg = &b1ref.Registry{Initialized: true, Phase: 2, GenesisCommitment: [32]byte{1}, ProfileHash: [32]byte{2}, Network: p.Network, WCert: p.WCert, Origin: p.Origin, RootRound: p.ClockRound, Epochs: map[uint64]b1state.Entry{}}
			for _, epoch := range p.Epochs {
				entry := b1state.Entry{Epoch: epoch.Epoch, BodyKind: 2, ActivationCommitID: [32]byte{3}, Start: epoch.Start, SigningScheme: 1, SigningConfigHash: [32]byte{4}}
				copy(entry.BodyID[:], decode(epoch.BodyID))
				if epoch.End != 0 {
					end := epoch.End
					entry.End = &end
				}
				for _, m := range epoch.Members {
					member := b1state.Member{NodeID: m.NodeID, Weight: m.Weight}
					copy(member.Key[:], decode(m.Key))
					entry.Members = append(entry.Members, member)
				}
				reg.Epochs[epoch.Epoch] = entry
			}
		}
		op := b1ref.OpMember
		if v.Op == "UC_V1" {
			op = b1ref.OpUC
		}
		if v.Op == "SHARED_SEAL_V1" {
			op = b1ref.OpShared
		}
		input := decode(v.Request)
		out, gas, e := b1ref.Run(op, input, reg, ^uint64(0))
		if v.Expected.Status == "error" {
			if !errors.Is(e, b1ref.ErrMalformed) || gas != ^uint64(0) || len(out) != 0 {
				panic(fmt.Sprintf("%s: expected exceptional malformed, got gas=%d out=%x err=%v", v.ID, gas, out, e))
			}
		} else if e != nil || gas != v.Expected.Gas || !bytes.Equal(out, decode(v.Expected.Output)) {
			panic(fmt.Sprintf("%s: gas=%d out=%x err=%v", v.ID, gas, out, e))
		}
	}
	fmt.Printf("PASS: pinned Go verified %d independently constructed Rust vectors (status, bytes, gas)\n", len(m.Vectors))
}
