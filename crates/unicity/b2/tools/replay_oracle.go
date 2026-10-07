// Run from a checkout of pin.json's oracleRevision:
// go run /path/to/replay_oracle.go /path/to/b2/protocol [--write]
// Replays every sealed case, then records/verifies the exact Kernel boundary for
// all B2 operations. Direct PrepareLock and Kernel payload decoding differ for
// zero amount; these expectations are obtained by executing Kernel itself.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"

	bp "github.com/unicitynetwork/bft-core/bridgeprofile"
)

type kernelCase struct {
	ID       string    `json:"id"`
	Expected bp.Expect `json:"expected"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string, v any) { b, err := os.ReadFile(path); must(err); must(json.Unmarshal(b, v)) }
func unhex(s string) []byte   { b, err := hex.DecodeString(s); must(err); return b }

func main() {
	root := os.Args[1]
	var pin struct {
		OracleRevision string `json:"oracleRevision"`
	}
	read(filepath.Join(root, "pin.json"), &pin)
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	must(err)
	if string(bytes.TrimSpace(head)) != pin.OracleRevision {
		panic("wrong oracle revision")
	}
	must(exec.Command("git", "diff", "--quiet", "HEAD", "--", "bridgeprofile").Run())
	var fs bp.FixtureSet
	read(filepath.Join(root, "vectors/config/fixtures.json"), &fs)
	files, err := filepath.Glob(filepath.Join(root, "vectors/*/cases.json"))
	must(err)
	total := 0
	kernels := []kernelCase{}
	for _, file := range files {
		var cf bp.CaseFile
		read(file, &cf)
		for _, c := range cf.Cases {
			got := bp.Replay(&fs, c)
			if !reflect.DeepEqual(got, c.Expected) {
				panic(fmt.Sprintf("%s: got %+v, want %+v", c.ID, got, c.Expected))
			}
			total++
			var input []byte
			switch c.Op {
			case "kernel":
				input = unhex(c.Input)
			case "prepareLock", "mint", "return":
				op := uint8(2)
				payload := unhex(c.Input)
				if c.Op == "mint" {
					op = 1
				}
				if c.Op == "prepareLock" {
					op = 0
					n, err := strconv.ParseUint(c.Aux["n"], 10, 64)
					must(err)
					amount, ok := new(big.Int).SetString(c.Aux["amount"], 10)
					if !ok {
						panic("amount")
					}
					payload = bp.PreparePayload(n, amount, payload)
				}
				input, err = bp.EncodeKernelInput(op, unhex(fs.Cfgs[c.Cfg].Cfg), payload)
				must(err)
			default:
				continue
			}
			out, err := bp.Kernel(input)
			expected := bp.Expect{Status: "ok", Output: hex.EncodeToString(out)}
			if err != nil {
				reason, family := bp.Reason(err)
				expected = bp.Expect{Status: "error", Reason: reason, Family: family}
			}
			kernels = append(kernels, kernelCase{c.ID, expected})
		}
	}
	if total != 336 || len(kernels) != 116 {
		panic(fmt.Sprintf("unexpected coverage: %d/%d", total, len(kernels)))
	}
	data, err := json.MarshalIndent(kernels, "", "  ")
	must(err)
	data = append(data, '\n')
	dest := filepath.Join(root, "kernel-expectations.json")
	if len(os.Args) == 3 && os.Args[2] == "--write" {
		must(os.WriteFile(dest, data, 0644))
	} else {
		existing, err := os.ReadFile(dest)
		must(err)
		if !bytes.Equal(data, existing) {
			panic("Kernel expectations differ")
		}
	}
	fmt.Printf("Replayed %d sealed cases; verified %d exact Kernel outcomes at %s\n", total, len(kernels), pin.OracleRevision)
}
