use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::{BlockNumberOrTag, Typed2718};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_rpc_types_engine::PayloadAttributes;
use eyre::OptionExt;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, HeaderForPayload, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpecBuilder, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_db::{
    mdbx::{tx::Tx, RO},
    DatabaseEnv,
};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{
    block::{BlockExecutionError, BlockValidationError},
    execute::{BlockBuilder, BlockBuilderOutcome, ExecutorTx},
    ConfigureEvm, NextBlockEnvAttributes,
};
use reth_node_api::{NodeTypesWithDBAdapter, PayloadBuilderError};
use reth_node_core::dirs::{DataDirPath, PlatformPath};
use reth_node_ethereum::{EthEvmConfig, EthereumNode};
use reth_payload_builder::{BlobSidecars, EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_primitives_traits::SignedTransaction;
use reth_provider::{
    providers::ReadOnlyConfig, BlockBodyIndicesProvider, BlockReader, ChainSpecProvider,
    DatabaseProvider, HeaderProvider, ProviderFactory, StateProviderFactory, TransactionsProvider,
};
use reth_revm::{
    cached::CachedReads, cancelled::CancelOnDrop, database::StateProviderDatabase, db::State,
};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

type BenchDbProvider =
    DatabaseProvider<Tx<RO>, NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>;

#[derive(Debug, Clone)]
pub struct ArtificialPayloadBuilder<EvmConfig = EthEvmConfig> {
    factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    evm_config: EvmConfig,
    target_gas_limit: u64,
    builder_config: EthereumBuilderConfig,
    // Track which transaction number to start from
    next_tx_num: u64,
}

impl<EvmConfig> ArtificialPayloadBuilder<EvmConfig> {
    pub fn new(
        factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
        target_gas_limit: u64,
        from_block: u64,
    ) -> Self {
        Self { factory, evm_config, builder_config, target_gas_limit, next_tx_num: 0 }
    }

    pub fn get_build_args(
        &self,
        from_block: u64,
    ) -> Result<BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>, PayloadBuilderError>
    {
        let provider = self.factory.provider()?;

        let parent_header = provider
            .sealed_header(from_block)
            .map_err(PayloadBuilderError::other)?
            .unwrap_or_default();

        let attributes = EthPayloadBuilderAttributes::new(
            parent_header.hash(),
            PayloadAttributes {
                timestamp: parent_header.timestamp + 12,
                prev_randao: parent_header.mix_hash,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: None,
                parent_beacon_block_root: parent_header.parent_beacon_block_root,
            },
        );

        let config = PayloadConfig::new(Arc::new(parent_header), attributes);
        let args =
            BuildArguments::new(CachedReads::default(), config, CancelOnDrop::default(), None);
        Ok(args)
    }
}

impl<EvmConfig> PayloadBuilder for ArtificialPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        build_artificial_payload(
            self.factory.clone(),
            self.evm_config.clone(),
            self.builder_config.clone(),
            args,
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        // For benchmarking, we don't need to race empty payloads
        MissingPayloadBehaviour::AwaitInProgress
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, HeaderForPayload<Self::BuiltPayload>>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        // For benchmarking, you probably don't need this
        // But you could build a minimal block with no transactions
        Err(PayloadBuilderError::MissingPayload)
    }
}

pub fn build_artificial_payload<EvmConfig>(
    factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    evm_config: EvmConfig,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
{
    let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;
    let PayloadConfig { parent_header, attributes } = config;

    // Get a provider from the factory for this operation
    let client = factory.provider()?;
    let state_provider = factory.history_by_block_hash(parent_header.hash())?;

    let state = StateProviderDatabase::new(&state_provider);
    let mut db = State::builder().with_database(state).with_bundle_update().build();

    let mut builder = evm_config
        .builder_for_next_block(
            &mut db,
            &parent_header,
            NextBlockEnvAttributes {
                timestamp: attributes.timestamp(),
                suggested_fee_recipient: attributes.suggested_fee_recipient(),
                prev_randao: attributes.prev_randao(),
                gas_limit: builder_config.desired_gas_limit,
                parent_beacon_block_root: attributes.parent_beacon_block_root(),
                withdrawals: Some(attributes.withdrawals().clone()),
            },
        )
        .map_err(PayloadBuilderError::other)?;

    let chain_spec = client.chain_spec();

    // Get transaction indices from parent block
    let indices =
        client.block_body_indices(parent_header.number).map_err(PayloadBuilderError::other)?;
    let mut start_tx_num = indices.map(|indices| indices.last_tx_num() + 1).unwrap_or(0);

    info!(
        target: "artificial_payload_builder",
        parent_number = parent_header.number,
        start_tx_num = start_tx_num,
        "Building artificial block"
    );

    // TODO: Fetch and execute transactions from the database starting at start_tx_num
    // Loop until you hit target_gas_limit or run out of transactions
    let mut cumulative_gas_used = 0;
    let mut total_fees = U256::ZERO;

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

    // initialize empty blob sidecars at first. If cancun is active then this will be populated by
    // blob sidecars if any.
    let mut blob_sidecars = BlobSidecars::Empty;

    let mut block_blob_count = 0;
    let mut block_transactions_rlp_length = 0;

    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
    let max_blob_count =
        blob_params.as_ref().map(|params| params.max_blob_count).unwrap_or_default();

    let is_osaka = chain_spec.is_osaka_active_at_timestamp(attributes.timestamp);

    'tx_fetch: while cumulative_gas_used < builder_config.desired_gas_limit {
        let tx_range = start_tx_num..start_tx_num + 100;

        let txs = client.transactions_by_tx_range(tx_range).map_err(PayloadBuilderError::other)?;

        for tx in txs {
            let recovered_tx = tx.try_into_recovered().unwrap();

            if recovered_tx.gas_limit() > builder_config.desired_gas_limit - cumulative_gas_used {
                trace!(target: "payload_builder", tx=?recovered_tx.hash(), builder_config.desired_gas_limit, cumulative_gas_used, "gas limit exceeded, completing block");
                break 'tx_fetch;
            }

            let gas_used = match builder.execute_transaction(recovered_tx.clone()) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        trace!(target: "payload_builder", %error, tx=?recovered_tx.hash(), "skipping nonce too low transaction");
                    } else {
                        // if the transaction is invalid, we can skip it and all of its
                        // descendants
                        trace!(target: "payload_builder", %error, tx=?recovered_tx.hash(), "skipping invalid transaction and its descendants");
                    }
                    continue
                }
                // this is an error that we should treat as fatal for this attempt
                Err(err) => return Err(PayloadBuilderError::evm(err)),
            };

            // update and add to total fees
            let miner_fee = recovered_tx
                .effective_tip_per_gas(parent_header.base_fee_per_gas().unwrap_or(0))
                .expect("fee is always valid; execution succeeded");
            total_fees += U256::from(miner_fee) * U256::from(gas_used);
            cumulative_gas_used += gas_used;
            start_tx_num += 1;
        }
    }

    let BlockBuilderOutcome { execution_result, block, .. } = builder.finish(&state_provider)?;

    let sealed_block = Arc::new(block.sealed_block().clone());
    debug!(target: "payload_builder", id=%attributes.id, sealed_block_header = ?sealed_block.sealed_header(), "sealed built block");

    let payload = EthBuiltPayload::new(attributes.id, sealed_block, total_fees, None);

    Ok(BuildOutcome::Better { payload, cached_reads })

    // Example transaction execution loop (you'll need to implement this):
    // let mut tx_num = start_tx_num;
    // while cumulative_gas_used < self.target_gas_limit {
    //     let tx = provider.transaction_by_id(tx_num)?
    //         .ok_or_eyre("Transaction not found")?;
    //
    //     match builder.execute_transaction(tx.clone()) {
    //         Ok(gas_used) => {
    //             cumulative_gas_used += gas_used;
    //             let base_fee = builder.evm_mut().block().basefee();
    //             let miner_fee = tx.effective_tip_per_gas(base_fee)
    //                 .expect("fee is always valid");
    //             total_fees += U256::from(miner_fee) * U256::from(gas_used);
    //             tx_num += 1;
    //         }
    //         Err(e) => {
    //             // Skip invalid transactions
    //             tx_num += 1;
    //             continue;
    //         }
    //     }
    // }

    // // Finish building
    // let BlockBuilderOutcome { execution_result, block, .. } =
    //     builder.finish(&state_provider)?;
    // let sealed_block = Arc::new(block.sealed_block().clone());

    // let requests = chain_spec
    //     .is_prague_active_at_timestamp(next_block_attrs.timestamp)
    //     .then_some(execution_result.requests);

    // // Increment for next call
    // self.build_from += 1;

    // // Create the built payload - use default PayloadId since we're not using Engine API
    // payload // service
    // Ok(EthBuiltPayload::new(
    //     Default::default(), // PayloadId doesn't matter for your use case
    //     sealed_block,
    //     total_fees,
    //     requests,
    // ))
}
