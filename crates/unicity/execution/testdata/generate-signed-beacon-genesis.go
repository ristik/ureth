// Run from bft-core's Go module: go run generate.go INPUT_JSON OUTPUT_DIR.
// Creates a test-only variant; never changes deployment configuration.
package main
import (
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "github.com/ethereum/go-ethereum/core"
 "github.com/ethereum/go-ethereum/crypto"
 "github.com/ethereum/go-ethereum/params"
 "github.com/ethereum/go-ethereum/rlp"
)
func must(err error){if err!=nil{panic(err)}}
func main(){
 raw,err:=os.ReadFile(os.Args[1]);must(err)
 var original core.Genesis;must(json.Unmarshal(raw,&original))
 originalHash:=original.ToBlock().Hash().Hex()
 if originalHash!="0x9d672f7822f0747687bcf1c4273cecac83f987871d215d5554d71fb1d1f6f1b9"{panic("original genesis mismatch: "+originalHash)}
 var doc map[string]any;must(json.Unmarshal(raw,&doc))
 alloc:=doc["alloc"].(map[string]any)
 // Deliberately public test key 1, not a deployment credential.
 key,err:=crypto.HexToECDSA(strings.Repeat("0",63)+"1");must(err)
 sender:=strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
 alloc[sender]=map[string]any{"balance":"0x56bc75e2d63100000","nonce":"0x0"}
 beacon:=strings.ToLower(params.BeaconRootsAddress.Hex())
 alloc[beacon]=map[string]any{"balance":"0x0","nonce":"0x1","code":"0x"+hex.EncodeToString(params.BeaconRootsCode)}
 output,err:=json.MarshalIndent(doc,"","  ");must(err);output=append(output,'\n')
 var final core.Genesis;must(json.Unmarshal(output,&final)); block:=final.ToBlock()
 header,err:=rlp.EncodeToBytes(block.Header());must(err)
 meta:=map[string]any{"generator":"go-ethereum v1.14.11 core.Genesis.ToBlock and rlp.EncodeToBytes; test-only variant", "source":"bft-core 9016a7e2 registrygenesis/testdata/funded-genesis-vector.json", "sourceGenesisHash":originalHash,"genesisHash":block.Hash().Hex(),"stateRoot":block.Root().Hex(),"headerRLP":"0x"+hex.EncodeToString(header),"testSigner":"public secp256k1 scalar 1","fundedAddress":sender,"beaconAddress":beacon,"beaconCodeHash":crypto.Keccak256Hash(params.BeaconRootsCode).Hex()}
 metadata,err:=json.MarshalIndent(meta,"","  ");must(err);metadata=append(metadata,'\n')
 must(os.WriteFile(filepath.Join(os.Args[2],"signed-beacon-genesis.json"),output,0644))
 must(os.WriteFile(filepath.Join(os.Args[2],"signed-beacon-genesis-oracle.json"),metadata,0644))
 fmt.Printf("genesis=%s state=%s sender=%s\n",block.Hash().Hex(),block.Root().Hex(),sender)
}
