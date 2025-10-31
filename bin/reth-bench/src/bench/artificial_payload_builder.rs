use alloy_consensus::Header as AlloyHeader;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, B256, U256};
use eyre::OptionExt;
use reth_chainspec::{ChainSpecBuilder, EthChainSpec, EthereumHardforks};
use reth_db::{
    mdbx::{tx::Tx, RO},
    DatabaseEnv,
};
use reth_ethereum_engine_primitives::{BlobSidecars, EthBuiltPayload};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, NextBlockEnvAttributes,
};
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_core::dirs::{DataDirPath, PlatformPath};
use reth_node_ethereum::{EthEvmConfig, EthereumNode};
use reth_provider::{
    providers::ReadOnlyConfig, BlockBodyIndicesProvider, BlockReader, ChainSpecProvider,
    DatabaseProvider, HeaderProvider, ProviderFactory, StateProviderFactory, TransactionsProvider,
};
use reth_revm::{database::StateProviderDatabase, db::State};
use std::sync::Arc;
use tracing::{info, warn};

type BenchDbProvider =
    DatabaseProvider<Tx<RO>, NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>;

type BenchProviderFactory = ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>;

pub struct ArtificialPayloadBuilder {
    client: Client,
    evm_config: EvmConfig,
    target_gas_limit: u64,
    builder_config: EthereumBuilderConfig,
    // Track which transaction number to start from
    next_tx_num: u64,
}

impl<Client, EvmConfig> ArtificialPayloadBuilder<Client, EvmConfig> {
    pub fn new(client: Client, evm_config: EvmConfig, builder_config: EthereumBuilderConfig, target_gas_limit: u64, from_block: u64) -> Self {
        Self { client, evm_config, builder_config, target_gas_limit, next_tx_num: 0 }
    }   
}

impl<Client, EvmConfig> PayloadBuilder for ArtificialPayloadBuilder<Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BlockReader
        + TransactionsProvider
        + HeaderProvider<Header = AlloyHeader>
        + Clone,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;
        let PayloadConfig { parent_header, attributes } = config;

        self.build_next_artificial_block()
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


    /// Build the next artificial block and return it as an EthBuiltPayload
    fn build_next_artificial_block(&mut self) -> eyre::Result<EthBuiltPayload> {
        let parent_block_number = self.build_from;

        // Get a provider from the factory for this operation
        let provider = self.factory.provider()?;
        let state_provider = self.factory.history_by_block_number(parent_block_number)?;

        let state = StateProviderDatabase::new(&state_provider);
        let mut db = State::builder().with_database(state).with_bundle_update().build();

        let parent_header =
            provider.sealed_header(parent_block_number)?.ok_or_eyre("Parent header not found")?;

        // Simple attributes for benchmarking
        let next_block_attrs = NextBlockEnvAttributes {
            timestamp: parent_header.timestamp + 12,
            suggested_fee_recipient: Address::ZERO,
            prev_randao: parent_header.mix_hash,
            gas_limit: self.target_gas_limit,
            parent_beacon_block_root: parent_header.parent_beacon_block_root,
            withdrawals: None,
        };

        let mut builder =
            self.evm_config.builder_for_next_block(&mut db, &parent_header, next_block_attrs)?;

        let chain_spec = self.factory.chain_spec();

        builder.apply_pre_execution_changes()?;

        // Get transaction indices from parent block
        let indices = provider.block_body_indices(parent_block_number)?.ok_or_eyre("No indices")?;
        let start_tx_num = indices.last_tx_num() + 1;

        info!(
            target: "artificial_payload_builder",
            parent_number = parent_block_number,
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

        todo!()

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
}
