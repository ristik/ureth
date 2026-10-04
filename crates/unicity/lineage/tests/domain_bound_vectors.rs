//! Byte-for-byte conformance with the Q1 domain-bound vote and timeout vectors
//! (`testdata/domain_bound_vectors.json`, identical to bft-core's `network/protocol/abdrc/testdata`
//! at the merged #394 commit `e33070b6`).
//!
//! For every vector the Rust preimage encoders must reproduce the signed bytes, their SHA-256
//! digest and every derived value (vote info, vote-info hash, native seal bytes) from the semantic
//! inputs alone, and every signature must verify under the vector's key. The wire bytes are read
//! independently (a test-side CBOR reader) and cross-checked against the inputs. The timeout
//! certificate's four signers are not given keys in the file: each key is recovered from that
//! signer's signature over the embedded legacy high QC, and the certificate's per-signer scheme-2
//! signature must then verify under, and recover to, that same key.
//!
//! The file holds votes (a committing one carries both signature components of a paired QC),
//! timeouts and a timeout certificate; it has no standalone scheme-2 quorum-certificate vector,
//! which arrives with Q1's paired-QC work (bft-core #396). That gap is recorded in the README.

mod support;

use reth_unicity_lineage::{
    votesig::{self, Anchor, Commit, Config, Timeout, VoteInfo},
    Kind,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use support::{array32, dec, hex, testdata, unhex, Enc, Val};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    name: String,
    scheme: u64,
    kind: String,
    inputs: serde_json::Value,
    signed_bytes_hex: String,
    digest_hex: String,
    public_key_hex: String,
    signatures_hex: BTreeMap<String, String>,
    wire_hex: String,
    derived_hex: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Set {
    network: u64,
    root_genesis_hex: String,
    vectors: Vec<Vector>,
}

const SEAL: u64 = 39005;
const ROUND_INFO: u64 = 39007;

fn load() -> (Set, Config) {
    let set: Set =
        serde_json::from_str(&testdata("domain_bound_vectors.json")).expect("vectors parse");
    let cfg = Config { network: set.network, genesis: array32(&set.root_genesis_hex) };
    (set, cfg)
}

fn num(v: &serde_json::Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or_else(|| panic!("input {k}"))
}

fn opt32(v: &serde_json::Value) -> Option<[u8; 32]> {
    v.as_str().map(array32)
}

/// A legacy seal's signed bytes: the tagged seal with its signature field null.
fn seal_sig_bytes(seal: &Val) -> Vec<u8> {
    let f = seal.tagged(SEAL).arr();
    let mut e = Enc::default();
    e.tag(SEAL).array(8);
    for item in &f[..7] {
        match item {
            Val::U(n) => e.uint(*n),
            Val::B(b) => e.bytes(b),
            Val::Null => e.null(),
            v => panic!("seal item {v:?}"),
        };
    }
    e.null();
    e.0
}

fn vote_info(v: &serde_json::Value) -> VoteInfo {
    VoteInfo {
        epoch: num(v, "epoch"),
        round: num(v, "round"),
        parent: num(v, "parentRound"),
        exec: array32(v["execStateHash"].as_str().expect("exec")),
    }
}

#[test]
fn the_set_is_the_seven_committed_vectors() {
    let (set, cfg) = load();
    assert_eq!(set.vectors.len(), 7);
    assert_eq!(cfg.vote_domain(), format!("root-vote/{}", set.root_genesis_hex));
    assert_eq!(cfg.timeout_domain(), format!("root-timeout/{}", set.root_genesis_hex));
    let schemes: Vec<_> = set.vectors.iter().map(|v| (v.scheme, v.kind.as_str())).collect();
    assert_eq!(schemes.iter().filter(|(s, _)| *s == 1).count(), 2);
    assert_eq!(schemes.iter().filter(|(s, _)| *s == 2).count(), 5);
}

#[test]
fn legacy_vectors_freeze_the_old_bytes() {
    let (set, _) = load();
    for v in set.vectors.iter().filter(|v| v.scheme == 1) {
        let signed = unhex(&v.signed_bytes_hex);
        let wire = dec(&unhex(&v.wire_hex));
        let key = unhex(&v.public_key_hex);
        let (sig_name, sig) = v.signatures_hex.iter().next().expect("a signature");
        let want_sig = match v.kind.as_str() {
            "vote" => {
                // the vote signs the ledger-commit-info seal bytes
                assert_eq!(seal_sig_bytes(&wire.arr()[1]), signed, "{}", v.name);
                assert_eq!(wire.arr()[3].text(), v.inputs["author"].as_str().unwrap());
                wire.arr()[4].bytes().to_vec()
            }
            "timeout" => {
                // round, epoch, high-QC round as 8-byte big-endian integers, then the author
                let mut want = Vec::new();
                for k in ["round", "epoch", "highQcRound"] {
                    want.extend(num(&v.inputs, k).to_be_bytes());
                }
                want.extend(v.inputs["author"].as_str().unwrap().as_bytes());
                assert_eq!(want, signed, "{}", v.name);
                wire.arr()[2].bytes().to_vec()
            }
            k => panic!("kind {k}"),
        };
        assert_eq!(votesig::digest(&signed), array32(&v.digest_hex), "{}", v.name);
        assert_eq!(hex(&want_sig), *sig, "{} wire carries the {sig_name} signature", v.name);
        assert!(votesig::verify_preimage(&key, &signed, &unhex(sig)), "{}", v.name);
    }
}

#[test]
fn domain_bound_votes_are_reproduced_byte_for_byte() {
    let (set, cfg) = load();
    let mut committing = 0;
    for v in set.vectors.iter().filter(|v| v.scheme == 2 && v.kind == "vote") {
        let vi = vote_info(&v.inputs);
        let commit = Commit {
            hash: opt32(&v.inputs["commitStateHash"]),
            round: num(&v.inputs, "commitRound"),
        };
        let key = unhex(&v.public_key_hex);
        let derived = v.derived_hex.as_ref().expect("derived values");

        let vi_bytes = cfg.vote_info_bytes(&vi).expect("vote info");
        assert_eq!(hex(&vi_bytes), derived["voteInfo"], "{}", v.name);
        let vh = cfg.vote_info_hash(&vi).expect("vote info hash");
        assert_eq!(hex(&vh), derived["voteInfoHash"], "{}", v.name);
        let pv = cfg.vote_preimage(&vi, &commit).expect("preimage");
        assert_eq!(hex(&pv), v.signed_bytes_hex, "{}", v.name);
        assert_eq!(hex(&votesig::digest(&pv)), v.digest_hex, "{}", v.name);
        let vote_sig = unhex(&v.signatures_hex["vote"]);
        assert!(votesig::verify_preimage(&key, &pv, &vote_sig), "{}: the vote signature", v.name);
        assert_eq!(
            votesig::recover_signer(&pv, &vote_sig).map(|k| k.to_vec()),
            Some(key.clone()),
            "{}: recovers to the signer",
            v.name
        );

        // the wire: [2, [voteInfo, ledgerCommitInfo, highQC, author, voteSignature,
        // sealSignature|null]]
        let wire = dec(&unhex(&v.wire_hex));
        assert_eq!(wire.arr()[0].uint(), 2);
        let m = wire.arr()[1].arr();
        let wvi = m[0].arr();
        assert_eq!(
            (wvi[0].uint(), wvi[1].uint(), wvi[2].uint()),
            (vi.epoch, vi.round, vi.parent),
            "{}",
            v.name
        );
        assert_eq!(wvi[3].bytes(), vi.exec);
        let seal = m[1].tagged(SEAL).arr();
        assert_eq!(seal[5].bytes(), vh, "{}: LedgerCommitInfo.PreviousHash is VH", v.name);
        assert_eq!(seal[2].uint(), commit.round, "{}", v.name);
        match commit.hash {
            Some(h) => assert_eq!(seal[6].bytes(), h),
            None => assert_eq!(seal[6], Val::Null),
        }
        assert_eq!(m[3].text(), v.inputs["author"].as_str().unwrap());
        assert_eq!(
            hex(m[4].bytes()),
            v.signatures_hex["vote"],
            "{}: the wire carries the vote signature",
            v.name
        );

        if commit.hash.is_some() {
            committing += 1;
            // the second component of the pair: the native seal signature over the ledger commit
            // info
            let native = seal_sig_bytes(&m[1]);
            assert_eq!(hex(&native), derived["nativeSealSigBytes"], "{}", v.name);
            let seal_sig = unhex(&v.signatures_hex["seal"]);
            assert_eq!(m[5].bytes(), seal_sig);
            assert!(
                votesig::verify_preimage(&key, &native, &seal_sig),
                "{}: the seal signature",
                v.name
            );
            assert_ne!(vote_sig, seal_sig);
        } else {
            assert_eq!(m[5], Val::Null, "a non-committing vote carries no seal signature");
            assert!(!v.signatures_hex.contains_key("seal"));
        }
    }
    assert_eq!(committing, 1);
}

fn timeout_of(v: &Vector) -> Timeout {
    let anchor = v.inputs["anchor"].as_object().map(|a| Anchor {
        genesis_id: array32(a["genesisId"].as_str().unwrap()),
        epoch: a["epoch"].as_u64().unwrap(),
        slot: a["slot"].as_u64().unwrap(),
    });
    Timeout {
        epoch: num(&v.inputs, "epoch"),
        round: num(&v.inputs, "round"),
        high_qc_round: num(&v.inputs, "highQcRound"),
        anchor,
        author: v.inputs["author"].as_str().unwrap().to_owned(),
    }
}

#[test]
fn domain_bound_timeouts_are_reproduced_byte_for_byte() {
    let (set, cfg) = load();
    let mut anchors = 0;
    for v in set.vectors.iter().filter(|v| v.scheme == 2 && v.kind == "timeout") {
        let t = timeout_of(v);
        let pt = cfg.timeout_preimage(&t).expect("preimage");
        assert_eq!(hex(&pt), v.signed_bytes_hex, "{}", v.name);
        assert_eq!(hex(&votesig::digest(&pt)), v.digest_hex, "{}", v.name);
        let key = unhex(&v.public_key_hex);
        let sig = unhex(&v.signatures_hex["timeout"]);
        assert!(votesig::verify_preimage(&key, &pt, &sig), "{}", v.name);
        assert_eq!(
            votesig::recover_signer(&pt, &sig).map(|k| k.to_vec()),
            Some(key.clone()),
            "{}",
            v.name
        );

        // the wire: [2, [[epoch, round, highQC|null, anchor?], author, signature, null]]
        let wire = dec(&unhex(&v.wire_hex));
        let m = wire.arr()[1].arr();
        let body = m[0].arr();
        assert_eq!((body[0].uint(), body[1].uint()), (t.epoch, t.round), "{}", v.name);
        assert_eq!(m[1].text(), t.author);
        assert_eq!(hex(m[2].bytes()), v.signatures_hex["timeout"]);
        match t.anchor {
            None => {
                let hqc = body[2].arr();
                assert_eq!(
                    hqc[0].tagged(ROUND_INFO).arr()[1].uint(),
                    t.high_qc_round,
                    "the high QC round is the QC's vote round"
                );
            }
            Some(a) => {
                anchors += 1;
                assert_eq!(body[2], Val::Null);
                let wa = body[3].arr(); // [genesisId, epoch, slot, stateRoot]: the state root is not signed
                assert_eq!(
                    (wa[0].bytes(), wa[1].uint(), wa[2].uint()),
                    (a.genesis_id.as_slice(), a.epoch, a.slot)
                );
                assert_eq!(wa.len(), 4);
            }
        }
    }
    assert_eq!(anchors, 1);
}

#[test]
fn the_timeout_certificate_signers_carry_different_high_qc_rounds() {
    let (set, cfg) = load();
    let v = set
        .vectors
        .iter()
        .find(|v| v.kind == "timeoutCertificate")
        .expect("the certificate vector");
    let wire = dec(&unhex(&v.wire_hex));
    assert_eq!(wire.arr()[0].uint(), 2);
    let tc = wire.arr()[1].arr();
    let head = tc[0].arr(); // [epoch, round, highQC]
    let (epoch, round) = (head[0].uint(), head[1].uint());
    assert_eq!((epoch, round), (num(&v.inputs, "epoch"), num(&v.inputs, "round")));
    let qc = head[2].arr();
    let qc_signed = seal_sig_bytes(&qc[1]);

    let known: BTreeMap<String, String> = [("1", "vote"), ("2", "timeout")]
        .iter()
        .filter_map(|(id, kind)| {
            let (set, _) = load();
            set.vectors
                .into_iter()
                .find(|v| v.scheme == 2 && v.kind == *kind)
                .map(|v| ((*id).to_owned(), v.public_key_hex))
        })
        .collect();

    let mut rounds = Vec::new();
    for (id, entry) in tc[1].map().iter().map(|(k, e)| (k.text().to_owned(), e)) {
        let [hqc_round, sig] = entry.arr() else { panic!("signer entry") };
        let (hqc_round, sig) = (hqc_round.uint(), sig.bytes());
        assert_eq!(hex(sig), v.signatures_hex[&id], "signer {id}");
        rounds.push(hqc_round);
        assert_eq!(
            hqc_round,
            v.inputs["highQcRoundsByAuthor"][&id].as_u64().unwrap(),
            "signer {id}"
        );

        // the signer's key, recovered from its signature over the embedded legacy QC
        let qc_sig = qc[2]
            .map()
            .iter()
            .find(|(k, _)| k.text() == id)
            .map(|(_, s)| s.bytes().to_vec())
            .expect("a QC signature");
        let key = votesig::recover_signer(&qc_signed, &qc_sig).expect("recoverable QC signature");
        if let Some(k) = known.get(&id) {
            assert_eq!(hex(&key), *k, "signer {id}: the recovered key is the vector's key");
        }
        let t =
            Timeout { epoch, round, high_qc_round: hqc_round, anchor: None, author: id.clone() };
        let pt = cfg.timeout_preimage(&t).expect("per-signer preimage");
        assert!(votesig::verify_preimage(&key, &pt, sig), "signer {id}");
        assert_eq!(votesig::recover_signer(&pt, sig), Some(key), "signer {id}");
    }
    rounds.sort_unstable();
    assert_eq!(rounds, [9, 10, 11, 11], "the signers' own high QC rounds differ");
}

#[test]
fn each_domain_binding_is_isolated() {
    let (set, cfg) = load();
    let v = set
        .vectors
        .iter()
        .find(|v| v.name == "domain-bound committing vote")
        .expect("committing vote");
    let vi = vote_info(&v.inputs);
    let commit =
        Commit { hash: opt32(&v.inputs["commitStateHash"]), round: num(&v.inputs, "commitRound") };
    let key = unhex(&v.public_key_hex);
    let sig = unhex(&v.signatures_hex["vote"]);
    let ok = |c: &Config, vi: &VoteInfo, m: &Commit| {
        votesig::verify_preimage(&key, &c.vote_preimage(vi, m).expect("preimage"), &sig)
    };
    assert!(ok(&cfg, &vi, &commit), "acceptance control");
    // network, genesis, epoch, round, parent, exec hash, commit hash and commit round each
    // separately void the signature
    assert!(!ok(&Config { network: cfg.network + 1, ..cfg }, &vi, &commit), "network");
    let mut g = cfg.genesis;
    g[0] ^= 1;
    assert!(!ok(&Config { genesis: g, ..cfg }, &vi, &commit), "root genesis");
    assert!(!ok(&cfg, &VoteInfo { epoch: vi.epoch + 1, ..vi }, &commit), "epoch");
    assert!(!ok(&cfg, &VoteInfo { round: vi.round + 1, ..vi }, &commit), "round");
    assert!(!ok(&cfg, &VoteInfo { parent: vi.parent - 1, ..vi }, &commit), "parent round");
    let mut e = vi.exec;
    e[31] ^= 1;
    assert!(!ok(&cfg, &VoteInfo { exec: e, ..vi }, &commit), "execution state hash");
    let mut h = commit.hash.unwrap();
    h[0] ^= 1;
    assert!(!ok(&cfg, &vi, &Commit { hash: Some(h), ..commit }), "commit state hash");
    assert!(!ok(&cfg, &vi, &Commit { round: commit.round - 1, ..commit }), "commit round");
    // a timeout signature is not a vote signature even over the same fields: the tag separates the
    // kinds
    let t = set.vectors.iter().find(|v| v.name == "domain-bound timeout").expect("timeout");
    let tsig = unhex(&t.signatures_hex["timeout"]);
    let tkey = unhex(&t.public_key_hex);
    let pv = cfg.vote_preimage(&vi, &commit).unwrap();
    assert!(!votesig::verify_preimage(&tkey, &pv, &tsig));
    assert!(
        !votesig::verify_preimage(&key, &cfg.timeout_preimage(&timeout_of(t)).unwrap(), &sig),
        "a vote signature is no timeout signature"
    );
}

#[test]
fn malformed_statements_and_signatures_are_refused_by_kind() {
    let (_, cfg) = load();
    let vi = VoteInfo { epoch: 2, round: 12, parent: 11, exec: [5; 32] };
    let code = |r: reth_unicity_lineage::Result<Vec<u8>>| r.expect_err("refused").kind();
    assert_eq!(code(cfg.vote_info_bytes(&VoteInfo { round: 0, ..vi })), Kind::Statement);
    assert_eq!(code(cfg.vote_info_bytes(&VoteInfo { parent: 12, ..vi })), Kind::Statement);
    assert_eq!(
        code(cfg.vote_preimage(&vi, &Commit { hash: None, round: 3 })),
        Kind::Statement,
        "half-empty commit pair"
    );
    assert_eq!(
        code(cfg.vote_preimage(&vi, &Commit { hash: Some([1; 32]), round: 0 })),
        Kind::Statement,
        "half-empty commit pair"
    );
    assert_eq!(
        code(cfg.vote_preimage(&vi, &Commit { hash: Some([1; 32]), round: 12 })),
        Kind::Statement,
        "commit round not below voting round"
    );
    assert_eq!(code(Config { genesis: [0; 32], ..cfg }.vote_info_bytes(&vi)), Kind::Config);
    let t = Timeout { epoch: 2, round: 12, high_qc_round: 11, anchor: None, author: "2".into() };
    assert!(cfg.timeout_preimage(&t).is_ok(), "acceptance control");
    assert_eq!(
        code(cfg.timeout_preimage(&Timeout { author: String::new(), ..t })),
        Kind::Statement
    );
    assert_eq!(code(cfg.timeout_preimage(&Timeout { round: 11, ..t.clone() })), Kind::Statement);
    let a = Anchor { genesis_id: [7; 32], epoch: 2, slot: 11 };
    assert!(cfg.timeout_preimage(&Timeout { anchor: Some(a), ..t.clone() }).is_ok());
    assert_eq!(
        code(
            cfg.timeout_preimage(&Timeout { anchor: Some(Anchor { epoch: 3, ..a }), ..t.clone() })
        ),
        Kind::Statement
    );
    assert_eq!(
        code(cfg.timeout_preimage(&Timeout { anchor: Some(Anchor { slot: 10, ..a }), ..t })),
        Kind::Statement
    );
    for (len, last, ok) in [
        (64, 0, true),
        (65, 0, true),
        (65, 1, true),
        (65, 2, false),
        (63, 0, false),
        (66, 0, false),
    ] {
        let mut s = vec![9u8; len];
        *s.last_mut().unwrap() = last;
        assert_eq!(votesig::check_signature_shape(&s).is_ok(), ok, "length {len} last byte {last}");
    }
}
