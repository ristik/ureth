package b1paired_test

// Generates the ureth B1 PR4 vectors. Run from bft-core's Go module at the pinned commit:
//
//	B1PR4_OUT=/path/to/dir go test -count=1 -run TestGenerateUrethPR4Vectors ./b1paired
//
// It writes b1-genesis.json (a funded, beacon-equipped variant of the B1 genesis), its oracle,
// and b1-vectors.json: a K=2 scenario whose Updates, root inputs and expected registry words
// come from bft-core's own b1state model and evmroot encoder. Rust executes the real registry
// runtime and must reproduce every addressed word.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func h32(parts ...string) [32]byte {
	return sha256.Sum256([]byte(strings.Join(parts, "/")))
}
func hx(b []byte) string       { return "0x" + hex.EncodeToString(b) }
func hx32(b [32]byte) string    { return hx(b[:]) }
func memberKey(seed string) (k [33]byte) {
	s := h32("b1pr4/key", seed)
	priv, err := crypto.ToECDSA(s[:])
	if err != nil {
		panic(err)
	}
	copy(k[:], crypto.CompressPubkey(&priv.PublicKey))
	return
}
func synthetic(epoch, kind, start uint64, members []b1state.Member) b1state.Entry {
	e := fmt.Sprint(epoch)
	return b1state.Entry{Epoch: epoch, BodyKind: kind, BodyID: h32("body", e), ActivationCommitID: h32("act", e), Start: start, SigningScheme: 2, SigningConfigHash: h32("cfg", e), Members: members}
}
func three(w [3]uint64) []b1state.Member {
	return []b1state.Member{{NodeID: "node-a", Key: memberKey("a"), Weight: w[0]}, {NodeID: "node-b", Key: memberKey("b"), Weight: w[1]}, {NodeID: "node-c", Key: memberKey("c"), Weight: w[2]}}
}

// wide has 64 members with maximal 128-byte identifiers sharing a 96-byte prefix.
func wide() []b1state.Member {
	prefix := strings.Repeat("p", 96)
	var out []b1state.Member
	for i := 0; i < 64; i++ {
		out = append(out, b1state.Member{NodeID: prefix + fmt.Sprintf("%032d", i), Key: memberKey(fmt.Sprint("wide", i)), Weight: uint64(i + 1)})
	}
	return out
}

type stepOut struct {
	Name          string            `json:"name"`
	N             uint64            `json:"n"`
	OriginRound   uint64            `json:"originRound"`
	OriginEpoch   uint64            `json:"originEpoch"`
	ParentHash    string            `json:"parentHash"`
	ParentNumber  uint64            `json:"parentNumber"`
	RootInput     string            `json:"rootInput"`
	Update        string            `json:"update"`
	UpdateHash    string            `json:"updateHash"`
	AdmissionGas  uint64            `json:"admissionGas"`
	Inserts       int               `json:"insertWrites"`
	Clears        int               `json:"clearWrites"`
	WriteAllow    uint64            `json:"writeAllowance"`
	Final         map[string]string `json:"final"`
	LiveEpochs    []uint64          `json:"liveEpochs"`
	Head          uint64            `json:"head"`
	OriginIdentity string           `json:"originIdentity"`
	RecordsImport  string           `json:"recordsImport"`
	RecordsHash    string           `json:"rootRecordsHash"`
	RecordsGas     uint64           `json:"recordsAdmissionGas"`
}

func TestGenerateUrethPR4Vectors(t *testing.T) {
	out := os.Getenv("B1PR4_OUT")
	if out == "" {
		t.Skip("B1PR4_OUT not set")
	}
	const w = 1
	f := b1fixture.New(t, w)
	p := f.Pair.Profile
	profileHash, err := p.Hash()
	require.NoError(t, err)

	// Funded, beacon-equipped variant of the exported genesis, with its oracle.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(f.Genesis.GenesisJSON(), &doc))
	alloc := doc["alloc"].(map[string]any)
	key, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	require.NoError(t, err)
	sender := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	alloc[sender] = map[string]any{"balance": "0x56bc75e2d63100000", "nonce": "0x0"}
	beacon := strings.ToLower(params.BeaconRootsAddress.Hex())
	alloc[beacon] = map[string]any{"balance": "0x0", "nonce": "0x1", "code": "0x" + hex.EncodeToString(params.BeaconRootsCode)}
	genesisJSON, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	genesisJSON = append(genesisJSON, '\n')
	var final core.Genesis
	require.NoError(t, json.Unmarshal(genesisJSON, &final))
	block := final.ToBlock()
	header, err := rlp.EncodeToBytes(block.Header())
	require.NoError(t, err)
	oracle := map[string]any{"generator": "bft-core b1paired TestGenerateUrethPR4Vectors; go-ethereum core.Genesis.ToBlock", "source": "bft-core ce9cad819 registrygenesis.GenerateB1 + b1fixture.New(W=1)", "sourceGenesisHash": f.Genesis.EVMGenesisHash().Hex(), "genesisHash": block.Hash().Hex(), "stateRoot": block.Root().Hex(), "headerRLP": hx(header), "testSigner": "public secp256k1 scalar 1", "fundedAddress": sender, "beaconAddress": beacon, "beaconCodeHash": crypto.Keccak256Hash(params.BeaconRootsCode).Hex()}
	oracleJSON, err := json.MarshalIndent(oracle, "", "  ")
	require.NoError(t, err)

	// Authenticated history model: the genesis entry plus synthetic successors.
	first, err := f.History.ForEpoch(1)
	require.NoError(t, err)
	genesis, err := f.History.B1Entries(first.Start())
	require.NoError(t, err)
	require.Len(t, genesis, 1)
	history := []b1state.Entry{genesis[0],
		synthetic(2, 2, 10, three([3]uint64{1, 1, 1})),
		synthetic(3, 3, 20, three([3]uint64{1, 1, 2})), // same keys, new weights
		synthetic(4, 3, 21, three([3]uint64{2, 2, 2})),
		synthetic(5, 3, 40, three([3]uint64{3, 1, 1})), // expires before it is ever projected
		synthetic(6, 3, 41, three([3]uint64{1, 3, 1})),
		synthetic(7, 3, 60, wide()),
	}
	// A root-epoch rotation reaches the execution registry only through an assignment
	// acknowledgement: the root epoch of every non-acknowledgement block equals the registry's
	// assigned root epoch. Single-epoch rotations are root-only acknowledgements; the skipped
	// epoch folds a supersession span and changes the shard assignment.
	type spec struct {
		name         string
		round, epoch uint64
	}
	specs := []spec{
		{"quiet-at-genesis-epoch", 5, 1},
		{"repeated-origin-no-op", 5, 1},
		{"rotation-expires-genesis-without-closure", 12, 2},
		{"quiet-in-new-epoch", 15, 2},
		{"rotation-closes-survivor-and-inserts", 20, 3},
		{"evicts-oldest-keeps-closed-survivor-and-wraps-ring", 21, 4},
		{"repeated-origin-keeps-moved-head", 21, 4},
		{"quiet-origin-prunes-end-equal-floor-and-wraps-head-back", 22, 4},
		{"quiet-after-prune", 24, 4},
		{"skips-expired-intermediate-epoch", 45, 6},
		{"closes-survivor-and-inserts-wide-entry", 60, 7},
	}
	genesisWords, err := b1state.GenesisWords(p, genesis[0])
	require.NoError(t, err)
	universe := map[[32]byte]bool{}
	mark := func(m map[[32]byte][32]byte) {
		for k := range m {
			universe[k] = true
		}
	}
	for _, e := range history {
		m, err := b1state.EntryStorage(e)
		require.NoError(t, err)
		mark(m)
	}
	for i := uint64(0); i <= w; i++ {
		universe[b1state.QueueSlot(i)] = true
	}
	universe[b1state.FixedSlot("b1.head")] = true
	universe[b1state.FixedSlot("b1.count")] = true

	parentOrigin := genesis[0].Start
	ring := b1state.Ring{Head: 0, OriginRound: parentOrigin, GenesisStart: genesis[0].Start, Entries: mustSelect(t, history, parentOrigin, w)}
	var steps []stepOut
	// The registry's assignment as the previous block left it.
	assignedRoot, assignedShard := uint64(1), uint64(0)
	assignedConf := f.Genesis.FullShardConfHash().Bytes()
	for i, s := range specs {
		n := uint64(i + 1)
		parent := h32("parent", fmt.Sprint(n))
		var ir evmroot.ShardInputRecord
		if n > 1 {
			state := h32("state", "quiet")
			ir = evmroot.ShardInputRecord{Round: n - 1, Epoch: assignedShard, PreviousHash: state[:], Hash: state[:], Timestamp: n - 1}
		}
		newShard, newConf := assignedShard, assignedConf
		var transitions [][]byte
		if s.epoch != assignedRoot {
			span, commitment := uint64(0), [32]byte{}
			if delta := s.epoch - assignedRoot; delta > 1 {
				newShard, span, commitment = assignedShard+delta, delta, h32("supersession", fmt.Sprint(n))
				c := h32("assignment", fmt.Sprint(n))
				newConf = c[:]
			}
			transitions = [][]byte{transitionBytes(assignedRoot, s.epoch, assignedShard, newShard, assignedConf, newConf, span, commitment, n, parent)}
		}
		stat, fee := h32("stat"), h32("fee")
		tr := evmroot.TechnicalRecord{Round: n, Epoch: newShard, Leader: "evm-node", StatHash: stat[:], FeeHash: fee[:]}
		trHash := technicalHash(tr)
		tree := h32("tree", fmt.Sprint(n))
		origin := evmroot.RootOriginV2{NetworkID: uint64(p.Network), RootRound: s.round, RootEpoch: s.epoch, ReferenceTime: n, UnicityTreeRoot: tree[:], InputVersion: 1, IR: ir, TRHash: trHash[:], ShardConfHash: newConf}
		identity := origin.Identity()

		expected := mustSelect(t, history, parentOrigin, w)
		end, entries, err := b1state.Delta(history, expected, parentOrigin, s.round, w)
		require.NoError(t, err)
		u := b1state.Update{Network: p.Network, RootGenesisID: p.RootGenesisID, ExecutionChainID: p.ExecutionChainID, ProfileHash: profileHash, ParentHash: parent, BlockNumber: n, OriginEpoch: s.epoch, OriginRound: s.round, OriginIdentity: identity, PriorTipEpoch: expected[len(expected)-1].Epoch, OldTipEnd: end, NewEntries: entries}
		raw := u.Bytes()
		_, gas, err := b1state.Admit(raw, p, p.SystemGas)
		require.NoError(t, err)
		next, changes, err := ring.Apply(u, w)
		require.NoError(t, err)
		require.Equal(t, mustSelect(t, history, s.round, w), next.Entries, "Apply and Select agree")
		updateHash := u.Hash()
		// The mandatory root-record import of an empty source log: no entries, the pinned genesis UC time, a zero target.
		imp := rootrecords.Import{Progress: 0, UCTime: p.GenesisUCTime}
		impRaw, err := imp.Encode()
		require.NoError(t, err)
		impHash := sha256.Sum256(impRaw)
		_, impGas, err := rootrecords.AdmitImport(impRaw, p.SystemGas)
		require.NoError(t, err)
		input := evmroot.RootInputV2{Version: 2, NetworkID: uint64(p.Network), PartitionID: 8, Round: n, CertifiedEpoch: assignedShard, AuthorizedEpoch: newShard, ParentHash: parent[:], Origin: origin, TE: tr, Transitions: transitions, B1UpdateHash: updateHash[:], RootRecordsHash: impHash[:]}
		require.NoError(t, input.Validate())
		allow, err := changes.WriteAllowance()
		require.NoError(t, err)
		ins, clr := 0, 0
		for _, wr := range changes.Trace {
			if wr.Clear {
				clr++
			} else {
				ins++
			}
		}
		final := map[string]string{}
		for k, v := range changes.Final {
			final[hx32(k)] = hx32(v)
			universe[k] = true
		}
		var live []uint64
		for _, e := range next.Entries {
			live = append(live, e.Epoch)
		}
		steps = append(steps, stepOut{Name: s.name, N: n, OriginRound: s.round, OriginEpoch: s.epoch, ParentHash: hx32(parent), ParentNumber: n - 1, RootInput: hx(input.Encode()), Update: hx(raw), UpdateHash: hx32(u.Hash()), AdmissionGas: gas, Inserts: ins, Clears: clr, WriteAllow: allow, Final: final, LiveEpochs: live, Head: next.Head, OriginIdentity: hx32(identity), RecordsImport: hx(impRaw), RecordsHash: hx32(impHash), RecordsGas: impGas})
		ring, parentOrigin = next, s.round
		assignedRoot, assignedShard, assignedConf = s.epoch, newShard, newConf
	}
	words := map[string]string{}
	for k := range universe {
		words[hx32(k)] = hx32(genesisWords[k])
	}
	keys := make([]string, 0, len(universe))
	for k := range words {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vec := map[string]any{
		"format": "unicity-b1-pr4-vectors",
		"source": "bft-core p85/pr1c-pin b1state model, evmroot encoder, rootrecords import, registrygenesis.GenerateB1; contracts 30bc153",
		"world": map[string]any{
			"network": p.Network, "executionChainId": p.ExecutionChainID, "wCert": p.WCert, "rootGenesisId": hx32(p.RootGenesisID),
			"runtimeHash": hx32(p.RuntimeHash), "profileHash": hx32(profileHash), "systemGas": p.SystemGas, "maxGas": p.MaxGas,
			"ordinaryCapacity": p.OrdinaryCapacity, "restGas": p.RestGas, "genesisUcTime": p.GenesisUCTime, "genesisHash": block.Hash().Hex(), "shardConfHash": hx(f.Genesis.FullShardConfHash().Bytes()),
		},
		"universe":     keys,
		"genesisWords": words,
		"steps":        steps,
	}
	vecJSON, err := json.MarshalIndent(vec, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(out, 0o755))
	for name, raw := range map[string][]byte{"b1-genesis.json": genesisJSON, "b1-genesis-oracle.json": append(oracleJSON, '\n'), "b1-vectors.json": append(vecJSON, '\n')} {
		require.NoError(t, os.WriteFile(filepath.Join(out, name), raw, 0o644))
	}
}

func mustSelect(t *testing.T, history []b1state.Entry, origin, w uint64) []b1state.Entry {
	got, err := b1state.Select(history, origin, w)
	require.NoError(t, err)
	return got
}
func cborHead(b []byte, major byte, v uint64) []byte {
	switch {
	case v < 24:
		return append(b, major<<5|byte(v))
	case v <= 0xff:
		return append(b, major<<5|24, byte(v))
	case v <= 0xffff:
		return append(b, major<<5|25, byte(v>>8), byte(v))
	case v <= 0xffffffff:
		return append(b, major<<5|26, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, major<<5|27, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// technicalHash is SHA-256 of the canonical [round, epoch, leader, statHash, feeHash].
func technicalHash(tr evmroot.TechnicalRecord) [32]byte {
	b := cborHead(nil, 4, 5)
	b = cborHead(b, 0, tr.Round)
	b = cborHead(b, 0, tr.Epoch)
	b = append(cborHead(b, 3, uint64(len(tr.Leader))), tr.Leader...)
	b = append(cborHead(b, 2, uint64(len(tr.StatHash))), tr.StatHash...)
	b = append(cborHead(b, 2, uint64(len(tr.FeeHash))), tr.FeeHash...)
	return sha256.Sum256(b)
}

// TestRegenerateV2RootInputVectors re-encodes every executable v2 source of the existing
// independent vector file as the twelve-field B1 root input, with Go's own encoder.
func TestRegenerateV2RootInputVectors(t *testing.T) {
	in, out := os.Getenv("B1PR4_V2_IN"), os.Getenv("B1PR4_V2_OUT")
	if in == "" || out == "" {
		t.Skip("B1PR4_V2_IN / B1PR4_V2_OUT not set")
	}
	raw, err := os.ReadFile(in)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	dec := func(v any) []byte {
		if v == nil {
			return nil
		}
		b, err := hex.DecodeString(strings.TrimPrefix(v.(string), "0x"))
		require.NoError(t, err)
		if b == nil {
			b = []byte{}
		}
		return b
	}
	num := func(v any) uint64 { return uint64(v.(float64)) }
	update := h32("b1pr4/v2-vector-update")
	recordsHash := h32("p85/v2-vector-records")
	for _, v := range doc["vectors"].([]any) {
		vec := v.(map[string]any)
		src := vec["source"].(map[string]any)
		ir := src["inputRecord"].(map[string]any)
		tech := src["technical"].(map[string]any)
		origin := evmroot.RootOriginV2{NetworkID: num(src["networkId"]), RootRound: num(src["rootRound"]), RootEpoch: num(src["rootEpoch"]), ReferenceTime: num(src["referenceTime"]), UnicityTreeRoot: dec(src["unicityTreeRoot"]), InputVersion: 1,
			IR: evmroot.ShardInputRecord{Round: num(ir["round"]), Epoch: num(ir["epoch"]), PreviousHash: dec(ir["previousHash"]), Hash: dec(ir["hash"]), Timestamp: num(ir["timestamp"]), BlockHash: dec(ir["blockHash"])},
			TRHash: dec(src["trHash"]), ShardConfHash: dec(src["shardConfHash"])}
		require.Equal(t, vec["origin"].(map[string]any)["cbor"], hx(origin.Encode()), vec["name"])
		var transitions [][]byte
		for _, tr := range src["transitions"].([]any) {
			transitions = append(transitions, dec(tr))
		}
		input := evmroot.RootInputV2{Version: num(src["version"]), NetworkID: num(src["networkId"]), PartitionID: num(src["partitionId"]), ShardID: dec(src["shardId"]), Round: num(src["authorizedRound"]), CertifiedEpoch: num(src["certifiedEpoch"]), AuthorizedEpoch: num(src["authorizedEpoch"]), ParentHash: dec(src["parentHash"]), Origin: origin,
			TE: evmroot.TechnicalRecord{Round: num(tech["round"]), Epoch: num(tech["epoch"]), Leader: tech["leader"].(string), StatHash: dec(tech["statHash"]), FeeHash: dec(tech["feeHash"])}, Transitions: transitions, B1UpdateHash: update[:], RootRecordsHash: recordsHash[:]}
		require.NoError(t, input.Validate())
		src["b1UpdateHash"] = hx32(update)
		src["rootRecordsHash"] = hx32(recordsHash)
		ri := vec["rootInput"].(map[string]any)
		fields := ri["fields"].([]any)
		ri["fields"] = append(fields, hx32(update), hx32(recordsHash))
		ri["cbor"] = hx(input.Encode())
		extra := input.ExtraData()
		ri["commitment"] = hx32(extra)
	}
	doc["note"] = fmt.Sprint(doc["note"], " Root inputs carry the twelfth field b1UpdateHash and the thirteenth rootRecordsHash and were re-encoded by bft-core's evmroot encoder (p85/pr1c-pin); origin encodings are unchanged.")
	body, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, append(body, '\n'), 0o644))
}

// transitionBytes encodes an acknowledged EVM transition and its acknowledgement exactly as the
// handoff package does, with the fixed identities the registry stores verbatim.
func transitionBytes(oldRoot, newRoot, oldShard, newShard uint64, oldConf, newConf []byte, span uint64, commitment [32]byte, round uint64, parent [32]byte) []byte {
	bstr := func(b []byte, v []byte) []byte { return append(cborHead(b, 2, uint64(len(v))), v...) }
	word := func(tag byte) []byte { return bytesRepeat(tag, 32) }
	ack := cborHead(nil, 4, 8)
	ack = append(cborHead(ack, 3, 19), "UNICITY_HANDOFF_ACK"...)
	ack = cborHead(ack, 0, 2)
	for _, w := range [][]byte{word(0x41), word(0x42), parent[:], parent[:], word(0x43)} {
		ack = bstr(ack, w)
	}
	ack = cborHead(ack, 0, round)
	t := cborHead(nil, 4, 13)
	t = append(cborHead(t, 3, 30), "UNICITY_HANDOFF_EVM_TRANSITION"...)
	t = cborHead(t, 0, 3)
	for _, v := range []uint64{oldRoot, newRoot, oldShard, newShard} {
		t = cborHead(t, 0, v)
	}
	t = bstr(t, oldConf)
	t = bstr(t, newConf)
	t = cborHead(t, 0, span)
	t = bstr(t, commitment[:])
	t = bstr(t, word(0x44))
	t = bstr(t, word(0x45))
	return bstr(t, ack)
}
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
