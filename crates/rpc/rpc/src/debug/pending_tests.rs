use super::*;
use alloy_consensus::{Header, TxLegacy};
use alloy_evm::Database;
use alloy_network::Ethereum;
use alloy_primitives::{hex, Signature, TxKind, U256};
use alloy_rpc_types_eth::{TransactionIndex, TransactionRequest};
use reth_chain_state::{ExecutedBlock, NewCanonicalChain};
use reth_chainspec::DEV;
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{BlockExecutorForEvm, ExecutionCtxFor};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::BlockExecutionOutput;
use reth_network_api::noop::NoopNetwork;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_provider::{
    providers::BlockchainProvider,
    test_utils::{create_test_provider_factory_with_chain_spec, MockNodeTypesWithDB},
};
use reth_rpc_eth_api::helpers::EthCall;
use reth_storage_api::BlockWriter;
use reth_transaction_pool::noop::NoopTransactionPool;
use revm::{database::BundleState, state::Bytecode};
use std::{
    error::Error,
    sync::atomic::{AtomicBool, Ordering},
};

// Like Ureth, this config reads the block's post-state while building the RPC environment
// and the replay executor. Clear pending just before the first of those reads.
#[derive(Clone, Debug)]
struct ClearPendingEvm {
    inner: EthEvmConfig,
    provider: BlockchainProvider<MockNodeTypesWithDB>,
    cleared: Arc<AtomicBool>,
}

impl ConfigureEvm for ClearPendingEvm {
    type Primitives = EthPrimitives;
    type Error = <EthEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <EthEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = <EthEvmConfig as ConfigureEvm>::BlockExecutorFactory;
    type BlockAssembler = <EthEvmConfig as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self.inner.block_executor_factory()
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtxFor<'_, Self>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }

    fn rpc_evm_env<DB: Database>(
        &self,
        header: &Header,
        _: Option<&Self::NextBlockEnvCtx>,
        post_state: impl FnOnce() -> Result<DB, Box<dyn Error + Send + Sync>>,
    ) -> Result<EvmEnvFor<Self>, Box<dyn Error + Send + Sync>> {
        let hash = header.hash_slow();
        if !self.cleared.swap(true, Ordering::Relaxed) {
            self.provider
                .canonical_in_memory_state()
                .update_chain(NewCanonicalChain::Commit { new: vec![] });
            assert!(matches!(
                self.provider.state_by_block_hash(hash),
                Err(reth_errors::ProviderError::StateForHashNotFound(missing)) if missing == hash
            ));
        }
        assert_eq!(post_state()?.block_hash(header.number)?, hash);
        Ok(self.evm_env(header)?)
    }

    fn rpc_executor_for_block<'a, DB: Database, PostState: Database>(
        &'a self,
        db: &'a mut State<DB>,
        block: &'a SealedBlock<Block>,
        post_state: impl FnOnce() -> Result<PostState, Box<dyn Error + Send + Sync>>,
    ) -> Result<BlockExecutorForEvm<'a, Self, DB>, Box<dyn Error + Send + Sync>> {
        let env = self.rpc_evm_env(block.header(), None, post_state)?;
        Ok(self.create_executor(self.evm_with_env(db, env), self.context_for_block(block)?))
    }
}

fn pending_call_fixture() -> (impl TraceExt<NetworkTypes = Ethereum> + EthCall, Arc<AtomicBool>) {
    let factory = create_test_provider_factory_with_chain_spec(DEV.clone());
    let genesis = RecoveredBlock::new_unhashed(
        Block { header: DEV.genesis_header().clone(), body: Default::default() },
        vec![],
    );
    let writer = factory.provider_rw().unwrap();
    writer.insert_block(&genesis).unwrap();
    writer.commit().unwrap();
    let provider = BlockchainProvider::new(factory).unwrap();
    let canonical = provider.canonical_in_memory_state();
    let header = Header {
        parent_hash: genesis.hash(),
        number: 1,
        timestamp: genesis.timestamp + 1,
        gas_limit: genesis.gas_limit,
        base_fee_per_gas: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        ..Default::default()
    };
    // The first transaction deploys a contract that stores calldata in slot zero or reads the
    // slot when calldata is empty. The second transaction writes one. An indexed call at 1
    // sees the deployed contract and its initial zero, while a full call sees the write.
    let runtime = hex!("3615600c57600035600055005b60005460005260206000f3");
    let mut init_code = hex!("6018600c60003960186000f3").to_vec();
    init_code.extend_from_slice(&runtime);
    let contract = Address::ZERO.create(0);
    let transactions = [
        TxLegacy {
            gas_limit: 100_000,
            to: TxKind::Create,
            input: init_code.into(),
            ..Default::default()
        },
        TxLegacy {
            nonce: 1,
            gas_limit: 100_000,
            to: TxKind::Call(contract),
            input: U256::ONE.to_be_bytes::<32>().to_vec().into(),
            ..Default::default()
        },
    ]
    .map(|tx| TransactionSigned::new_unhashed(tx.into(), Signature::test_signature()));
    let block = RecoveredBlock::new_unhashed(
        Block {
            header,
            body: alloy_consensus::BlockBody {
                transactions: transactions.into(),
                ..Default::default()
            },
        },
        vec![Address::ZERO; 2],
    );
    let code = Bytecode::new_raw(Bytes::copy_from_slice(&runtime));
    let code_hash = code.hash_slow();
    let info = revm::state::AccountInfo { nonce: 1, code_hash, ..Default::default() };
    let output = BlockExecutionOutput {
        state: BundleState::new(
            [(
                contract,
                None,
                Some(info),
                [(U256::ZERO, (U256::ZERO, U256::ONE))].into_iter().collect(),
            )],
            [[(contract, Some(None), [(U256::ZERO, U256::ZERO)])]],
            [(code_hash, code)],
        ),
        ..Default::default()
    };
    canonical.set_pending_block(ExecutedBlock::new(
        Arc::new(block),
        Arc::new(output),
        Default::default(),
    ));
    let cleared = Arc::new(AtomicBool::new(false));
    let evm = ClearPendingEvm {
        inner: EthEvmConfig::new(DEV.clone()),
        provider: provider.clone(),
        cleared: Arc::clone(&cleared),
    };
    let eth = crate::EthApi::builder(
        provider,
        NoopTransactionPool::default(),
        NoopNetwork::default(),
        evm,
    )
    .build();
    (eth, cleared)
}

fn call() -> TransactionRequest {
    TransactionRequest::default().to(Address::ZERO.create(0))
}

fn bundle() -> Bundle<TransactionRequest> {
    Bundle { transactions: vec![call()], block_override: None }
}

fn pending_context(transaction_index: Option<TransactionIndex>) -> Option<StateContext> {
    Some(StateContext { block_number: Some(BlockId::pending()), transaction_index })
}

fn assert_replayed_trace(trace: &GethTrace) {
    let GethTrace::Default(trace) = trace else { panic!("expected an opcode trace") };
    assert!(!trace.failed);
    assert_eq!(trace.return_value.as_ref(), &[0; 32]);
}

#[tokio::test]
async fn pending_call_many_survives_clearing_pending() {
    let (eth, cleared) = pending_call_fixture();
    let result = eth.call_many(vec![bundle()], pending_context(None), None).await.unwrap();
    assert!(cleared.load(Ordering::Relaxed));
    assert_eq!(
        result[0][0].value,
        Some(Bytes::copy_from_slice(&U256::from(1).to_be_bytes::<32>()))
    );
}

#[tokio::test]
async fn pending_trace_call_many_survives_clearing_pending() {
    let (eth, cleared) = pending_call_fixture();
    let debug =
        DebugApi::new(eth, BlockingTaskGuard::new(1), &Runtime::test(), futures::stream::empty());
    let result = debug
        .debug_trace_call_many(
            vec![bundle()],
            pending_context(Some(TransactionIndex::Index(1))),
            None,
        )
        .await
        .unwrap();
    assert!(cleared.load(Ordering::Relaxed));
    assert_replayed_trace(&result[0][0]);
}

#[tokio::test]
async fn pending_trace_call_at_index_survives_clearing_pending() {
    let (eth, cleared) = pending_call_fixture();
    let debug =
        DebugApi::new(eth, BlockingTaskGuard::new(1), &Runtime::test(), futures::stream::empty());
    let result = debug
        .debug_trace_call(
            call(),
            Some(BlockId::pending()),
            GethDebugTracingCallOptions { tx_index: Some(1), ..Default::default() },
        )
        .await
        .unwrap();
    assert!(cleared.load(Ordering::Relaxed));
    assert_replayed_trace(&result);
}
