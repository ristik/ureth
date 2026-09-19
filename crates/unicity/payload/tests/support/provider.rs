//! Test-only complete in-memory parent state, with real Ethereum trie roots.
//! Unused proof APIs panic instead of returning plausible empty evidence.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{
    root::{state_root, storage_root},
    TrieAccount,
};
use reth_primitives_traits::{Account, Bytecode as RethBytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage,
    MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::{
    database::BundleState,
    state::{AccountInfo, Bytecode},
    Database,
};
use std::{collections::BTreeMap, convert::Infallible};

#[derive(Clone, Debug, Default)]
pub(crate) struct FixtureProvider {
    accounts: BTreeMap<Address, AccountInfo>,
    storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    code: BTreeMap<B256, Bytecode>,
    hashes: BTreeMap<u64, B256>,
}

impl FixtureProvider {
    pub(crate) fn from_json(json: &str) -> Self {
        let genesis: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut this = Self::default();
        for (address, entry) in genesis["alloc"].as_object().unwrap() {
            let address: Address = address.parse().unwrap();
            let balance: U256 = entry["balance"].as_str().unwrap().parse().unwrap();
            let nonce = entry.get("nonce").map_or(0, |n| {
                n.as_u64().unwrap_or_else(|| {
                    u64::from_str_radix(n.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
                })
            });
            let bytes: Bytes =
                entry.get("code").and_then(|v| v.as_str()).unwrap_or("0x").parse().unwrap();
            let code = Bytecode::new_raw(bytes);
            let code_hash = code.hash_slow();
            this.code.insert(code_hash, code.clone());
            this.accounts.insert(
                address,
                AccountInfo { balance, nonce, code_hash, code: Some(code), ..Default::default() },
            );
            if let Some(slots) = entry.get("storage").and_then(|v| v.as_object()) {
                for (key, value) in slots {
                    let key: U256 = key.parse().unwrap();
                    let value: U256 = value.as_str().unwrap().parse().unwrap();
                    if value != U256::ZERO {
                        this.storage.entry(address).or_default().insert(key, value);
                    }
                }
            }
        }
        this
    }

    pub(crate) fn signed_genesis() -> Self {
        let this = Self::from_json(include_str!("../../testdata/signed-beacon-genesis.json"));
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/signed-beacon-genesis-oracle.json"))
                .unwrap();
        assert_eq!(this.root(), oracle["stateRoot"].as_str().unwrap().parse::<B256>().unwrap());
        this
    }

    pub(crate) fn set_block_hash(&mut self, number: u64, hash: B256) {
        self.hashes.insert(number, hash);
    }

    pub(crate) fn apply_bundle(&mut self, bundle: &BundleState) {
        self.code.extend(bundle.contracts.iter().map(|(hash, code)| (*hash, code.clone())));
        for (address, account) in &bundle.state {
            if account.status.was_destroyed() {
                self.storage.remove(address);
            }
            match &account.info {
                None => {
                    self.accounts.remove(address);
                    self.storage.remove(address);
                }
                Some(info) => {
                    self.accounts.insert(*address, info.clone());
                    if let Some(code) = &info.code {
                        self.code.insert(info.code_hash, code.clone());
                    }
                    for (key, value) in &account.storage {
                        let slots = self.storage.entry(*address).or_default();
                        if value.present_value == U256::ZERO {
                            slots.remove(key);
                        } else {
                            slots.insert(*key, value.present_value);
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn root(&self) -> B256 {
        self.root_with(HashedPostState::default())
    }

    fn root_with(&self, changes: HashedPostState) -> B256 {
        let mut accounts: BTreeMap<B256, Account> = self
            .accounts
            .iter()
            .map(|(address, info)| {
                (
                    keccak256(address),
                    Account {
                        nonce: info.nonce,
                        balance: info.balance,
                        bytecode_hash: Some(info.code_hash),
                    },
                )
            })
            .collect();
        let mut storages: BTreeMap<B256, BTreeMap<B256, U256>> = self
            .storage
            .iter()
            .map(|(address, slots)| {
                (
                    keccak256(address),
                    slots
                        .iter()
                        .map(|(key, value)| (keccak256(key.to_be_bytes::<32>()), *value))
                        .collect(),
                )
            })
            .collect();
        for (address, account) in changes.accounts {
            if let Some(account) = account {
                accounts.insert(address, account);
            } else {
                accounts.remove(&address);
                storages.remove(&address);
            }
        }
        for (address, change) in changes.storages {
            let slots = storages.entry(address).or_default();
            if change.wiped {
                slots.clear();
            }
            for (key, value) in change.storage {
                if value == U256::ZERO {
                    slots.remove(&key);
                } else {
                    slots.insert(key, value);
                }
            }
        }
        state_root(accounts.into_iter().map(|(address, account)| {
            let slots = storages.remove(&address).unwrap_or_default();
            (
                address,
                TrieAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    code_hash: account.bytecode_hash.unwrap_or_else(|| keccak256([])),
                    storage_root: storage_root(slots),
                },
            )
        }))
    }
}

impl Database for FixtureProvider {
    type Error = Infallible;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.code.get(&hash).expect("known code hash").clone())
    }
    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&address).and_then(|s| s.get(&key)).copied().unwrap_or_default())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.hashes.get(&number).copied().unwrap_or_default())
    }
}
impl AccountReader for FixtureProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        Ok(self.accounts.get(address).map(|info| Account {
            nonce: info.nonce,
            balance: info.balance,
            bytecode_hash: Some(info.code_hash),
        }))
    }
}
impl BytecodeReader for FixtureProvider {
    fn bytecode_by_hash(&self, hash: &B256) -> ProviderResult<Option<RethBytecode>> {
        Ok(self.code.get(hash).cloned().map(RethBytecode))
    }
}
impl BlockHashReader for FixtureProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        Ok(self.hashes.get(&number).copied())
    }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        Ok((start..end).filter_map(|n| self.hashes.get(&n).copied()).collect())
    }
}
impl StateProvider for FixtureProvider {
    fn storage(&self, address: Address, key: B256) -> ProviderResult<Option<U256>> {
        Ok(self.storage.get(&address).and_then(|s| s.get(&U256::from_be_bytes(key.0))).copied())
    }
}
impl HashedPostStateProvider for FixtureProvider {
    fn hashed_post_state(&self, bundle: &BundleState) -> ProviderResult<HashedPostState> {
        let mut result = HashedPostState::default();
        for (address, account) in &bundle.state {
            let address = keccak256(address);
            result.accounts.insert(
                address,
                account.info.as_ref().map(|info| Account {
                    nonce: info.nonce,
                    balance: info.balance,
                    bytecode_hash: Some(info.code_hash),
                }),
            );
            let mut storage = HashedStorage::new(account.status.was_destroyed());
            for (key, value) in &account.storage {
                storage.storage.insert(keccak256(key.to_be_bytes::<32>()), value.present_value);
            }
            result.storages.insert(address, storage);
        }
        Ok(result)
    }
}
impl StateRootProvider for FixtureProvider {
    fn state_root(&self, state: HashedPostState) -> ProviderResult<B256> {
        Ok(self.root_with(state))
    }
    fn state_root_with_updates(
        &self,
        state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.root_with(state), TrieUpdates::default()))
    }
    fn state_root_from_nodes(&self, _: TrieInput) -> ProviderResult<B256> {
        panic!("unused node-cache root API")
    }
    fn state_root_from_nodes_with_updates(
        &self,
        _: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        panic!("unused node-cache root API")
    }
}
impl StorageRootProvider for FixtureProvider {
    fn storage_root(&self, _: Address, _: HashedStorage) -> ProviderResult<B256> {
        panic!("unused storage root API")
    }
    fn storage_proof(&self, _: Address, _: B256, _: HashedStorage) -> ProviderResult<StorageProof> {
        panic!("unused proof API")
    }
    fn storage_multiproof(
        &self,
        _: Address,
        _: &[B256],
        _: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        panic!("unused proof API")
    }
}
impl StateProofProvider for FixtureProvider {
    fn proof(&self, _: TrieInput, _: Address, _: &[B256]) -> ProviderResult<AccountProof> {
        panic!("unused proof API")
    }
    fn multiproof(&self, _: TrieInput, _: MultiProofTargets) -> ProviderResult<MultiProof> {
        panic!("unused proof API")
    }
    fn witness(
        &self,
        _: TrieInput,
        _: HashedPostState,
        _: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        panic!("unused proof API")
    }
}
