//! Pinned Go conformance and isolated infrastructure/registry failures.
use alloy_primitives::U256;
use reth_unicity_b1::{
    entry_slot, fixed_slot, member_slot, run, Error, Malformed, Operation, RegistryRead,
};
use serde_json::Value;
use std::collections::BTreeMap;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[derive(Default, Debug)]
struct State {
    words: BTreeMap<U256, U256>,
    reads: Vec<U256>,
}
impl RegistryRead for State {
    type Error = ();
    fn sload(&mut self, key: U256) -> Result<U256, ()> {
        self.reads.push(key);
        Ok(*self.words.get(&key).unwrap_or(&U256::ZERO))
    }
}
fn state(v: &Value) -> State {
    let mut s = State::default();
    for (name, val) in
        [("genesisCommitment", 1), ("phase", 2), ("b1.initialized", 1), ("b1.profileHash", 2)]
    {
        s.words.insert(fixed_slot(name), U256::from(val));
    }
    for (name, field) in [
        ("b1.network", "network"),
        ("b1.wCert", "wCert"),
        ("clock.rootRound", "clockRound"),
        ("origin.rootEpoch", "origin"),
    ] {
        s.words.insert(fixed_slot(name), U256::from(v[field].as_u64().unwrap_or(0)));
    }
    if let Some(epochs) = v["epochs"].as_array() {
        for e in epochs {
            let epoch = e["epoch"].as_u64().unwrap();
            let members = e["members"].as_array().unwrap();
            let total: u64 = members.iter().map(|m| m["weight"].as_u64().unwrap()).sum();
            let end = e["end"].as_u64().unwrap();
            let fields = [
                U256::from(1),
                U256::from(2),
                U256::from_be_slice(&hex(e["bodyID"].as_str().unwrap())),
                U256::from(3),
                U256::from(e["start"].as_u64().unwrap()),
                U256::from(end),
                U256::from(u64::from(end != 0)),
                U256::from(1),
                U256::from(4),
                U256::from(members.len()),
                U256::from(total),
            ];
            for (f, w) in fields.into_iter().enumerate() {
                s.words.insert(entry_slot(epoch, f as u64), w);
            }
            for (j, m) in members.iter().enumerate() {
                let id = m["nodeID"].as_str().unwrap().as_bytes();
                let key = hex(m["key"].as_str().unwrap());
                let mut words = [[0u8; 32]; 8];
                words[0] = U256::from(id.len()).to_be_bytes::<32>();
                for (i, b) in id.iter().enumerate() {
                    words[1 + i / 32][i % 32] = *b;
                }
                words[5].copy_from_slice(&key[..32]);
                words[6][0] = key[32];
                words[7] = U256::from(m["weight"].as_u64().unwrap()).to_be_bytes::<32>();
                for (f, w) in words.into_iter().enumerate() {
                    s.words.insert(member_slot(epoch, j as u64, f as u64), U256::from_be_bytes(w));
                }
            }
        }
    }
    s
}
fn malformed(s: &str) -> Malformed {
    match s {
        "ErrTruncated" => Malformed::Truncated,
        "ErrTrailingBytes" => Malformed::Trailing,
        "ErrVersion" => Malformed::Version,
        "ErrFlags" => Malformed::Flags,
        "ErrCount" => Malformed::Count,
        "ErrNonCanonical" | "ErrDuplicateMapKey" => Malformed::Canonical,
        "ErrForbiddenCBOR" => Malformed::Cbor,
        "ErrInvalidUTF8" => Malformed::Utf8,
        "ErrShape" | "ErrRSMTLength" => Malformed::Shape,
        "ErrShardEncoding" | "ErrShardTooDeep" => Malformed::Shard,
        "ErrSigFormat" => Malformed::Signature,
        "ErrInputTooLarge" | "ErrUCTooLarge" | "ErrTooManySigs" | "ErrNodeIDTooLong" |
        "ErrTooManySiblings" | "ErrTooManySteps" | "ErrDepth" | "ErrSummaryTooLong" |
        "ErrValueTooLarge" => Malformed::Limit,
        s => panic!("unknown error {s}"),
    }
}
fn check_go_vectors(filter: Option<&str>) {
    let manifest: Value = serde_json::from_str(include_str!("testdata/go-4ba487e.json")).unwrap();
    let mut failures = Vec::new();
    for v in manifest["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        if filter.is_some_and(|f| f != id) {
            continue;
        }
        let op = match v["op"].as_str().unwrap() {
            "UC_V1" => Operation::Uc,
            "SHARED_SEAL_V1" => Operation::Shared,
            _ => Operation::Member,
        };
        let input = hex(v["request"].as_str().unwrap());
        let mut s = state(&v["preState"]);
        let result = run(op, &input, u64::MAX, &mut s);
        let expected = &v["expected"];
        if expected["status"] == "error" {
            let want = Err(Error::Malformed(malformed(expected["sentinel"].as_str().unwrap())));
            if result != want {
                failures.push(format!("{id}: {result:?}, want {want:?}"));
            }
            assert!(s.reads.is_empty(), "{id}: malformed reads");
        } else {
            let gas = expected["gas"].as_u64().unwrap();
            let out = hex(expected["output"].as_str().unwrap());
            match result {
                Ok(result) if result.gas == gas && result.bytes.as_slice() == out => {}
                r => failures
                    .push(format!("{id}: {r:?}, want gas {gas} valid {}", expected["valid"])),
            }
            let exact = run(op, &input, gas, &mut s);
            assert!(exact.is_ok(), "{id}: exact gas {exact:?}");
            let mut fresh = state(&v["preState"]);
            assert_eq!(run(op, &input, gas - 1, &mut fresh), Err(Error::OutOfGas), "{id}: gas-1");
            assert!(fresh.reads.is_empty(), "{id}: OOG read");
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn fixture(id: &str) -> Value {
    let m: Value = serde_json::from_str(include_str!("testdata/go-4ba487e.json")).unwrap();
    m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap().clone()
}
#[test]
fn registry_invariant_errors_are_exact_and_isolated() {
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    let base = state(&v["preState"]);
    let mut cases = vec![
        (fixed_slot("genesisCommitment"), U256::ZERO),
        (fixed_slot("b1.profileHash"), U256::ZERO),
        (fixed_slot("b1.initialized"), U256::ZERO),
        (fixed_slot("phase"), U256::from(3)),
        (fixed_slot("b1.network"), U256::from(65536)),
        (fixed_slot("b1.wCert"), U256::MAX),
    ];
    for (f, val) in [
        (0, U256::from(2)),
        (1, U256::ZERO),
        (1, U256::from(4)),
        (2, U256::ZERO),
        (3, U256::ZERO),
        (6, U256::from(2)),
        (5, U256::from(1)),
        (7, U256::ZERO),
        (7, U256::from(3)),
        (8, U256::ZERO),
        (9, U256::ZERO),
        (9, U256::from(65)),
        (10, U256::ZERO),
        (10, U256::from(5)),
        (4, U256::MAX),
    ] {
        cases.push((entry_slot(7, f), val));
    }
    cases.push((member_slot(7, 0, 0), U256::ZERO));
    cases.push((member_slot(7, 0, 0), U256::from(129)));
    cases.push((member_slot(7, 0, 0), U256::MAX));
    cases.push((member_slot(7, 0, 6), U256::from(1)));
    cases.push((member_slot(7, 0, 7), U256::ZERO));
    cases.push((member_slot(7, 0, 7), U256::MAX));
    cases.push((member_slot(7, 0, 5), U256::ZERO));
    for (k, val) in cases {
        let mut s = State { words: base.words.clone(), reads: vec![] };
        s.words.insert(k, val);
        assert_eq!(
            run(Operation::Uc, &input, u64::MAX, &mut s),
            Err(Error::Registry),
            "slot {k} value {val}"
        );
    }
    let mut s = State { words: base.words.clone(), reads: vec![] };
    s.words.insert(member_slot(7, 0, 7), U256::ZERO);
    s.words.insert(entry_slot(7, 10), U256::from(3));
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    let mut s = State { words: base.words.clone(), reads: vec![] };
    s.words.insert(entry_slot(7, 9), U256::from(65));
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    assert_eq!(s.reads.len(), 19, "invalid member count must not allocate or read members");
    // A wrapped sum agrees with the stored total and does not overflow the
    // signing subset; checked member accumulation is the only rejecting guard.
    let mut s = State { words: base.words.clone(), reads: vec![] };
    s.words.insert(member_slot(7, 3, 7), U256::from(u64::MAX));
    s.words.insert(entry_slot(7, 10), U256::from(2));
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    // Invalid UTF-8 in the last (non-signing) ID preserves its ordering even
    // under lossy decoding, so neither sorting nor crypto masks the check.
    let mut s = State { words: base.words.clone(), reads: vec![] };
    let mut id = s.words[&member_slot(7, 3, 1)].to_be_bytes::<32>();
    id[0] = 0xff;
    s.words.insert(member_slot(7, 3, 1), U256::from_be_bytes(id));
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    // Valid closed end; equality, reversed interval, and canonical word width.
    for end in [0, 899, 900] {
        let mut s = State { words: base.words.clone(), reads: vec![] };
        s.words.insert(entry_slot(7, 6), U256::from(1));
        s.words.insert(entry_slot(7, 5), U256::from(end));
        assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    }
    // Metadata for an absent epoch cannot carry stale words.
    let mut s = State { words: base.words.clone(), reads: vec![] };
    s.words.insert(entry_slot(7, 0), U256::ZERO);
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s), Err(Error::Registry));
    // Duplicate/unsorted IDs, duplicate keys, nonzero padding, invalid UTF-8.
    for mode in 0..5 {
        let mut s = State { words: base.words.clone(), reads: vec![] };
        match mode {
            0 => {
                let val = s.words[&member_slot(7, 0, 1)];
                s.words.insert(member_slot(7, 1, 1), val);
            }
            1 => {
                let val = s.words[&member_slot(7, 3, 1)];
                s.words.insert(member_slot(7, 0, 1), val);
            }
            2 => {
                for f in [5, 6] {
                    let val = s.words[&member_slot(7, 0, f)];
                    s.words.insert(member_slot(7, 1, f), val);
                }
            }
            3 => {
                s.words.insert(member_slot(7, 0, 4), U256::from(1));
            }
            _ => {
                s.words.insert(member_slot(7, 0, 1), U256::MAX);
            }
        }
        assert_eq!(
            run(Operation::Uc, &input, u64::MAX, &mut s),
            Err(Error::Registry),
            "mode {mode}"
        );
    }
}
#[test]
fn ordered_source_reads_and_phase_unknown_epoch() {
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    let mut s = state(&v["preState"]);
    let true_out = run(Operation::Uc, &input, u64::MAX, &mut s).unwrap();
    let mut expected: Vec<_> = [
        "genesisCommitment",
        "phase",
        "b1.initialized",
        "b1.network",
        "b1.wCert",
        "b1.profileHash",
        "clock.rootRound",
        "origin.rootEpoch",
    ]
    .into_iter()
    .map(fixed_slot)
    .collect();
    expected.extend((0..11).map(|f| entry_slot(7, f)));
    for j in 0..4 {
        expected.extend((0..8).map(|f| member_slot(7, j, f)));
    }
    assert_eq!(s.reads, expected);
    s.words.insert(fixed_slot("phase"), U256::from(1));
    s.reads.clear();
    let out = run(Operation::Uc, &input, u64::MAX, &mut s).unwrap();
    assert_eq!(out.bytes[63], 0);
    assert_eq!(out.gas, true_out.gas);
    assert_eq!(s.reads, expected);
    s.words.insert(fixed_slot("phase"), U256::from(2));
    for f in 0..11 {
        s.words.remove(&entry_slot(7, f));
    }
    s.reads.clear();
    let out = run(Operation::Uc, &input, u64::MAX, &mut s).unwrap();
    assert_eq!(out.bytes[63], 0);
    assert_eq!(s.reads.len(), 19);
}
#[test]
fn full_scan_and_debits_precede_host_access() {
    struct Fail;
    impl RegistryRead for Fail {
        type Error = &'static str;
        fn sload(&mut self, _: U256) -> Result<U256, Self::Error> {
            Err("unavailable historical state")
        }
    }
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    assert_eq!(
        run(Operation::Uc, &input, u64::MAX, &mut Fail),
        Err(Error::Host("unavailable historical state"))
    );
    assert_eq!(run(Operation::Uc, &input, 0, &mut Fail), Err(Error::OutOfGas));
    let bad = fixture("frozen.malformed-last");
    let input = hex(bad["request"].as_str().unwrap());
    assert_eq!(
        run(Operation::Shared, &input, u64::MAX, &mut Fail),
        Err(Error::Malformed(Malformed::Shape))
    );
}

#[test]
fn journal_values_warmth_revert_and_provider_status() {
    use alloy_evm::{
        eth::EthEvmContext,
        precompiles::{Precompile, PrecompileInput},
        EvmInternals,
    };
    use alloy_primitives::Address;
    use reth_unicity_b1::{provider::B1Precompile, REGISTRY};
    use revm::{
        context::JournalTr, database::InMemoryDB, handler::precompile_output_to_interpreter_result,
        interpreter::InstructionResult,
    };
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    let s = state(&v["preState"]);
    let mut db = InMemoryDB::default();
    for (k, val) in &s.words {
        db.insert_account_storage(REGISTRY, *k, *val).unwrap();
    }
    let mut ctx = EthEvmContext::new(db, Default::default());
    let pc = B1Precompile::new(Operation::Uc);
    assert!(!pc.supports_caching());
    assert!(!B1Precompile::new(Operation::Uc).into_dyn().supports_caching());
    assert!(!B1Precompile::new(Operation::Shared).into_dyn().supports_caching());
    assert!(!B1Precompile::new(Operation::Shared).supports_caching());
    assert!(B1Precompile::new(Operation::Member).supports_caching());
    fn call(
        pc: &B1Precompile,
        ctx: &mut EthEvmContext<InMemoryDB>,
        data: &[u8],
        gas: u64,
    ) -> revm::precompile::PrecompileResult {
        pc.call(PrecompileInput {
            data,
            gas,
            reservoir: 0,
            caller: Address::ZERO,
            value: U256::ZERO,
            is_static: true,
            internals: EvmInternals::from_context(ctx),
            target_address: Address::ZERO,
            bytecode_address: Address::ZERO,
        })
    }
    let checkpoint = ctx.journaled_state.checkpoint();
    let cold = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(cold.bytes[63], 1);
    // Normal subsequent journal SLOAD is warm after both true and false.
    let key = fixed_slot("b1.network");
    let after = EvmInternals::from_context(&mut ctx).sload(REGISTRY, key).unwrap();
    assert!(!after.is_cold);
    let warm = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(cold, warm);
    ctx.journaled_state.checkpoint_revert(checkpoint);
    let after = EvmInternals::from_context(&mut ctx).sload(REGISTRY, key).unwrap();
    assert!(after.is_cold);
    // Backing DB remains network 3, but current journal value 4 must win.
    let cp = ctx.journaled_state.checkpoint();
    EvmInternals::from_context(&mut ctx).sstore(REGISTRY, key, U256::from(4)).unwrap();
    let changed = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(changed.bytes[63], 0);
    assert_eq!(changed.gas_used, cold.gas_used);
    assert!(
        !EvmInternals::from_context(&mut ctx).sload(REGISTRY, entry_slot(7, 10)).unwrap().is_cold
    );
    ctx.journaled_state.checkpoint_revert(cp);
    let restored = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(restored.bytes[63], 1);
    // Normal conversion consumes the complete forwarded gas and clears output.
    for (data, gas, want) in [
        (vec![2, 0, 0, 1], 123456, InstructionResult::PrecompileError),
        (input.clone(), cold.gas_used - 1, InstructionResult::PrecompileOOG),
    ] {
        let out = call(&pc, &mut ctx, &data, gas).unwrap();
        let result = precompile_output_to_interpreter_result(out, gas);
        assert_eq!(result.result, want);
        assert!(result.output.is_empty());
        assert_eq!(result.gas.remaining(), 0);
    }
    // Impossible admitted state follows the host channel, never caller halt.
    EvmInternals::from_context(&mut ctx)
        .sstore(REGISTRY, fixed_slot("b1.initialized"), U256::ZERO)
        .unwrap();
    assert!(
        matches!(call(&pc,&mut ctx,&input,u64::MAX),Err(revm::precompile::PrecompileError::Fatal(ref msg)) if msg == "impossible admitted B1 registry")
    );
}

#[allow(dead_code)]
#[path = "../examples/vectors.rs"]
mod generator;
#[test]
fn independently_constructed_requests_match_kernel_verdicts() {
    let generated = generator::generate();
    let go: Value = serde_json::from_str(include_str!("testdata/go-4ba487e.json")).unwrap();
    for v in generated["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let op = match v["op"].as_str().unwrap() {
            "UC_V1" => Operation::Uc,
            "SHARED_SEAL_V1" => Operation::Shared,
            _ => Operation::Member,
        };
        let mut s = state(&v["preState"]);
        let input = hex(v["request"].as_str().unwrap());
        let result = run(op, &input, u64::MAX, &mut s);
        if v["expected"]["status"] == "error" {
            let want = if id.starts_with("rust.") {
                Malformed::Shape
            } else {
                let g = go["vectors"].as_array().unwrap().iter().find(|g| g["id"] == id).unwrap();
                malformed(g["expected"]["sentinel"].as_str().unwrap())
            };
            assert_eq!(result, Err(Error::Malformed(want)), "{id}");
        } else {
            let out = result.unwrap();
            assert_eq!(
                out.bytes.as_slice(),
                hex(v["expected"]["output"].as_str().unwrap()),
                "{id}"
            );
            assert_eq!(out.gas, v["expected"]["gas"].as_u64().unwrap(), "{id}");
        }
    }
}
#[test]
fn maximum_member_reads_and_unequal_seals_are_bounded() {
    let v = fixture("quorum.max.all");
    let mut s = state(&v["preState"]);
    let input = hex(v["request"].as_str().unwrap());
    assert_eq!(run(Operation::Uc, &input, u64::MAX, &mut s).unwrap().bytes[63], 1);
    assert_eq!(s.reads.len(), 531);
    let v = fixture("cert.shared.sigcount-3-4.false");
    let mut s = state(&v["preState"]);
    let input = hex(v["request"].as_str().unwrap());
    let out = run(Operation::Shared, &input, u64::MAX, &mut s).unwrap();
    assert_eq!(out.bytes[63], 0);
    assert_eq!(s.reads.len(), 8);
    assert_eq!(out.gas, v["expected"]["gas"].as_u64().unwrap());
}

macro_rules! vector_tests { ($($name:ident => $id:literal,)*) => { $(#[test] fn $name() { check_go_vectors(Some($id)); })* }; }
vector_tests! {
    vector_cert_single_ok => "cert.single.ok",
    vector_cert_shared_ok => "cert.shared.ok",
    vector_cert_shared_single_ok => "cert.shared.single.ok",
    vector_cert_uc_shard_ok => "cert.uc.shard.ok",
    vector_cert_repeat_ir_ok => "cert.repeat-ir.ok",
    vector_cert_subset_a_ok => "cert.subset-a.ok",
    vector_cert_subset_b_ok => "cert.subset-b.ok",
    vector_cert_shared_mixed_subsets_false => "cert.shared.mixed-subsets.false",
    vector_cert_shared_sigcount_3_4_false => "cert.shared.sigcount-3-4.false",
    vector_cert_shared_sigcount_4_3_false => "cert.shared.sigcount-4-3.false",
    vector_cert_neg_network => "cert.neg.network",
    vector_cert_neg_partition => "cert.neg.partition",
    vector_cert_neg_shard_bit => "cert.neg.shard-bit",
    vector_cert_neg_config => "cert.neg.config",
    vector_cert_neg_trhash => "cert.neg.trhash",
    vector_cert_neg_ir_state => "cert.neg.ir-state",
    vector_cert_neg_expected_state => "cert.neg.expected-state",
    vector_cert_neg_expected_ir => "cert.neg.expected-ir",
    vector_cert_neg_root => "cert.neg.root",
    vector_cert_neg_epoch => "cert.neg.epoch",
    vector_cert_neg_signed_byte => "cert.neg.signed-byte",
    vector_cert_neg_signer_key => "cert.neg.signer-key",
    vector_cert_neg_raw_concat_fold => "cert.neg.raw-concat-fold",
    vector_cert_shared_max_8_ok => "cert.shared.max-8.ok",
    vector_cert_shared_count_9 => "cert.shared.count-9",
    vector_cert_shared_order => "cert.shared.order",
    vector_cert_shared_order_shard => "cert.shared.order-shard",
    vector_cert_shared_duplicate => "cert.shared.duplicate",
    vector_cert_neg_ir_invalid => "cert.neg.ir-invalid",
    vector_cert_neg_seal_timestamp => "cert.neg.seal-timestamp",
    vector_seal_sigs_null => "seal.sigs-null",
    vector_seal_sigs_empty => "seal.sigs-empty",
    vector_quorum_short => "quorum.short",
    vector_quorum_dup_map_key => "quorum.dup-map-key",
    vector_quorum_unknown_signer => "quorum.unknown-signer",
    vector_quorum_bad_extra => "quorum.bad-extra",
    vector_quorum_sig_r_zero => "quorum.sig.r-zero",
    vector_quorum_sig_s_zero => "quorum.sig.s-zero",
    vector_quorum_sig_r_n => "quorum.sig.r-n",
    vector_quorum_sig_high_s => "quorum.sig.high-s",
    vector_quorum_sig_short => "quorum.sig.short",
    vector_quorum_sig_v255 => "quorum.sig.v255",
    vector_quorum_sig_v2 => "quorum.sig.v2",
    vector_quorum_sig_v_present => "quorum.sig.v-present",
    vector_quorum_sig_v_ignored => "quorum.sig.v-ignored",
    vector_quorum_max_exact => "quorum.max.exact",
    vector_quorum_max_short => "quorum.max.short",
    vector_quorum_max_all => "quorum.max.all",
    vector_time_start_eq_ok => "time.start.eq.ok",
    vector_time_start_before => "time.start.before",
    vector_time_end_last_ok => "time.end.last.ok",
    vector_time_end_eq => "time.end.eq",
    vector_time_open_not_origin => "time.open.not-origin",
    vector_time_age_wcert_ok => "time.age.wcert.ok",
    vector_time_age_wcert_1 => "time.age.wcert+1",
    vector_time_future => "time.future",
    vector_time_wcert_zero_current_ok => "time.wcert-zero.current.ok",
    vector_time_wcert_zero_old => "time.wcert-zero.old",
    vector_time_seal_epoch_after_origin => "time.seal-epoch.after-origin",
    vector_time_epoch_missing => "time.epoch.missing",
    vector_time_network_registry => "time.network.registry",
    vector_paths_shard_depth_255_ok => "paths.shard-depth-255.ok",
    vector_paths_shard_depth_256_ok => "paths.shard-depth-256.ok",
    vector_paths_unicity_steps_32_ok => "paths.unicity-steps-32.ok",
    vector_enc_shard_no_terminator => "enc.shard.no-terminator",
    vector_enc_shard_empty => "enc.shard.empty",
    vector_enc_shard_depth_257 => "enc.shard.depth-257",
    vector_enc_shard_34_bytes => "enc.shard.34-bytes",
    vector_enc_header_version => "enc.header.version",
    vector_enc_header_flags => "enc.header.flags",
    vector_enc_header_count_zero => "enc.header.count-zero",
    vector_enc_header_uc_count_2 => "enc.header.uc-count-2",
    vector_enc_header_truncated => "enc.header.truncated",
    vector_enc_trailing => "enc.trailing",
    vector_enc_truncated => "enc.truncated",
    vector_enc_cbor_nonminimal_int => "enc.cbor.nonminimal-int",
    vector_enc_cbor_wrong_tag => "enc.cbor.wrong-tag",
    vector_enc_cbor_float => "enc.cbor.float",
    vector_enc_cbor_indefinite => "enc.cbor.indefinite",
    vector_enc_cbor_depth_17 => "enc.cbor.depth-17",
    vector_enc_cbor_depth_16 => "enc.cbor.depth-16",
    vector_enc_cbor_huge_bytes_length => "enc.cbor.huge-bytes-length",
    vector_enc_cbor_huge_array_count => "enc.cbor.huge-array-count",
    vector_enc_cbor_invalid_utf8 => "enc.cbor.invalid-utf8",
    vector_enc_cbor_map_order => "enc.cbor.map-order",
    vector_enc_ir_summary_257 => "enc.ir.summary-257",
    vector_paths_shard_truncated_sibling => "paths.shard.truncated-sibling",
    vector_paths_shard_extra_sibling => "paths.shard.extra-sibling",
    vector_paths_shard_sibling_value => "paths.shard.sibling-value",
    vector_paths_unicity_wrong_path => "paths.unicity.wrong-path",
    vector_paths_unicity_step_value => "paths.unicity.step-value",
    vector_bound_shard_siblings_257 => "bound.shard-siblings-257",
    vector_bound_unicity_steps_33 => "bound.unicity-steps-33",
    vector_bound_signatures_65 => "bound.signatures-65",
    vector_bound_seal_node_id_129 => "bound.seal-node-id-129",
    vector_bound_call_262145 => "bound.call-262145",
    vector_bound_uc_24577 => "bound.uc-24577",
    vector_gas_4sigs_valid => "gas.4sigs.valid",
    vector_gas_4sigs_last_invalid => "gas.4sigs.last-invalid",
    vector_res_uc_length_u32max => "res.uc-length-u32max",
    vector_res_shard_length_u16max => "res.shard-length-u16max",
    vector_res_uc_length_past_end => "res.uc-length-past-end",
    vector_frozen_signature_length_0 => "frozen.signature-length-0",
    vector_frozen_signature_length_63 => "frozen.signature-length-63",
    vector_frozen_signature_length_66 => "frozen.signature-length-66",
    vector_frozen_signature_null => "frozen.signature-null",
    vector_frozen_malformed_last => "frozen.malformed-last",
    vector_frozen_unsorted_malformed_last => "frozen.unsorted-malformed-last",
    vector_frozen_null_shard => "frozen.null-shard",
    vector_frozen_null_unicity => "frozen.null-unicity",
    vector_frozen_null_siblings_depth_one => "frozen.null-siblings-depth-one",
    vector_frozen_null_sibling_value => "frozen.null-sibling-value",
    vector_weighted_below => "weighted.below",
    vector_weighted_at => "weighted.at",
    vector_weighted_above => "weighted.above",
    vector_rsmt_single_leaf_ok => "rsmt.single-leaf.ok",
    vector_rsmt_empty_value_ok => "rsmt.empty-value.ok",
    vector_rsmt_value_4096_ok => "rsmt.value-4096.ok",
    vector_rsmt_small_ok => "rsmt.small.ok",
    vector_rsmt_small_leaf0_ok => "rsmt.small.leaf0.ok",
    vector_rsmt_small_leaf4_ok => "rsmt.small.leaf4.ok",
    vector_rsmt_small_leaf8_ok => "rsmt.small.leaf8.ok",
    vector_rsmt_neg_key => "rsmt.neg.key",
    vector_rsmt_neg_value => "rsmt.neg.value",
    vector_rsmt_neg_root => "rsmt.neg.root",
    vector_rsmt_neg_zero_root => "rsmt.neg.zero-root",
    vector_rsmt_neg_sibling_order => "rsmt.neg.sibling-order",
    vector_rsmt_neg_sibling_value => "rsmt.neg.sibling-value",
    vector_rsmt_neg_bitmap_bit => "rsmt.neg.bitmap-bit",
    vector_rsmt_neg_no_region => "rsmt.neg.no-region",
    vector_rsmt_neg_truncated_sibling => "rsmt.neg.truncated-sibling",
    vector_rsmt_neg_extra_sibling => "rsmt.neg.extra-sibling",
    vector_rsmt_neg_partial_sibling => "rsmt.neg.partial-sibling",
    vector_rsmt_neg_version => "rsmt.neg.version",
    vector_rsmt_neg_flags => "rsmt.neg.flags",
    vector_rsmt_neg_count_2 => "rsmt.neg.count-2",
    vector_rsmt_neg_short_header => "rsmt.neg.short-header",
    vector_rsmt_neg_truncated_value => "rsmt.neg.truncated-value",
    vector_rsmt_neg_value_length_u32max => "rsmt.neg.value-length-u32max",
    vector_rsmt_neg_value_4097 => "rsmt.neg.value-4097",
    vector_rsmt_neg_too_large => "rsmt.neg.too-large",
    vector_rsmt_depth_255_ok => "rsmt.depth-255.ok",
    vector_rsmt_depth_256_ok => "rsmt.depth-256.ok",
    vector_rsmt_depth_256_neg_sibling => "rsmt.depth-256.neg.sibling",
}

#[test]
fn provider_database_failure_aborts_execution() {
    use alloy_evm::{
        eth::EthEvmContext,
        precompiles::{Precompile, PrecompileInput},
        EvmInternals,
    };
    use alloy_primitives::{Address, B256};
    use reth_unicity_b1::provider::B1Precompile;
    use revm::{
        database_interface::{DBErrorMarker, Database},
        state::{AccountInfo, Bytecode},
    };
    #[derive(Debug)]
    struct Unavailable;
    impl std::fmt::Display for Unavailable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("historical storage unavailable")
        }
    }
    impl std::error::Error for Unavailable {}
    impl DBErrorMarker for Unavailable {}
    #[derive(Debug)]
    struct Fail;
    impl Database for Fail {
        type Error = Unavailable;
        fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Unavailable> {
            Ok(Some(AccountInfo::default()))
        }
        fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Unavailable> {
            Err(Unavailable)
        }
        fn storage(&mut self, _: Address, _: U256) -> Result<U256, Unavailable> {
            Err(Unavailable)
        }
        fn block_hash(&mut self, _: u64) -> Result<B256, Unavailable> {
            Err(Unavailable)
        }
    }
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    let mut ctx = EthEvmContext::new(Fail, Default::default());
    let result = B1Precompile::new(Operation::Uc).call(PrecompileInput {
        data: &input,
        gas: u64::MAX,
        reservoir: 0,
        caller: Address::ZERO,
        value: U256::ZERO,
        is_static: true,
        internals: EvmInternals::from_context(&mut ctx),
        target_address: Address::ZERO,
        bytecode_address: Address::ZERO,
    });
    assert!(
        matches!(result,Err(revm::precompile::PrecompileError::Fatal(ref msg)) if msg == "historical storage unavailable")
    );
}

#[test]
fn initial_debit_wins_over_malformed_scanning() {
    let mut state = State::default();
    for op in [Operation::Uc, Operation::Shared, Operation::Member] {
        assert_eq!(run(op, &[2, 0, 0, 1], 0, &mut state), Err(Error::OutOfGas));
    }
    assert!(state.reads.is_empty());
    assert_eq!(
        run(Operation::Uc, &vec![0; 262145], 0, &mut state),
        Err(Error::Malformed(Malformed::Limit))
    );
}

#[test]
fn actual_staticcall_warms_downstream_sload_opcode() {
    use alloy_evm::{eth::EthEvmBuilder, Evm, EvmEnv};
    use alloy_primitives::{Address, Bytes, TxKind};
    use reth_unicity_b1::{provider::B1Precompile, REGISTRY};
    use revm::{
        context::TxEnv,
        database::InMemoryDB,
        state::{AccountInfo, Bytecode},
    };
    let v = fixture("cert.single.ok");
    let input = hex(v["request"].as_str().unwrap());
    let caller = Address::repeat_byte(0x11);
    for (invoke, network, want) in [(false, 3, 2107), (true, 3, 107), (true, 4, 107)] {
        let mut s = state(&v["preState"]);
        s.words.insert(fixed_slot("b1.network"), U256::from(network));
        let mut db = InMemoryDB::default();
        for (k, val) in s.words {
            db.insert_account_storage(REGISTRY, k, val).unwrap();
        }
        let mut code = Vec::new();
        if invoke {
            // Copy calldata, STATICCALL 0x0100, discard its success flag. A
            // shaped false call warms exactly the same storage as a true call.
            code.extend([
                0x36, 0x5f, 0x5f, 0x37, 0x60, 0x40, 0x5f, 0x36, 0x5f, 0x61, 0x01, 0x00, 0x5a, 0xfa,
                0x50,
            ]);
        }
        code.extend([0x5a, 0x7f]);
        code.extend(fixed_slot("b1.network").to_be_bytes::<32>());
        code.extend([0x54, 0x50, 0x5a, 0x90, 0x03, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        db.insert_account_info(
            REGISTRY,
            AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
        );
        db.insert_account_info(caller, AccountInfo { balance: U256::MAX, ..Default::default() });
        let mut env = EvmEnv::default();
        env.cfg_env.spec = revm::primitives::hardfork::SpecId::CANCUN;
        let mut evm = EthEvmBuilder::new(db, env).build();
        for op in [Operation::Uc, Operation::Shared, Operation::Member] {
            assert!(evm.precompiles_mut().get(&op.address()).is_none());
        }
        evm.precompiles_mut().apply_precompile(&Operation::Uc.address(), |_| {
            Some(B1Precompile::new(Operation::Uc).into_dyn())
        });
        let result = evm
            .transact(TxEnv {
                caller,
                kind: TxKind::Call(REGISTRY),
                gas_limit: 10_000_000,
                data: Bytes::copy_from_slice(&input),
                ..Default::default()
            })
            .unwrap()
            .result;
        assert!(result.is_success(), "{result:?}");
        assert_eq!(
            U256::from_be_slice(result.output().unwrap()),
            U256::from(want),
            "invoke={invoke} network={network}"
        );
    }
}
