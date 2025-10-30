use std::sync::Arc;

use alloy_consensus::Header;
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, B256};
use reth_ethereum_engine_primitives::{BlobSidecars, EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_node_api::{NodeTypesWithDBAdapter, PayloadBuilderError, PayloadBuilderAttributes};
use reth_node_core::dirs::{DataDirPath, PlatformPath};
use reth_node_ethereum::EthEvmConfig;
use reth_revm::{db::State, database::StateProviderDatabase};
use reth_revm::context_interface::Block;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_storage_api::{BlockReader, StateProvider, TransactionsProvider};
use reth_provider::{ChainSpecProvider, DatabaseProvider, HeaderProvider, StateProviderFactory};
use reth_chainspec::{ChainSpecBuilder, EthChainSpec, EthereumHardforks};
use reth_ethereum_payload_builder::{EthereumBuilderConfig};
use reth_basic_payload_builder::{BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig};
use reth_node_ethereum::EthereumNode;
use reth_provider::providers::ReadOnlyConfig;
use reth_ethereum_primitives::{EthPrimitives};
use reth_db::{DatabaseEnv, mdbx::{RO, tx::Tx}};
use reth_primitives_traits::{BlockHeader, SealedHeader};
use eyre::{Context, OptionExt};
use serde_json::to_vec;
use tracing::{debug, info};


type BenchDbProvider = DatabaseProvider<
    Tx<RO>,
    NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>,
>;

use alloy_consensus::Header as AlloyHeader;

pub fn build_artificial_payload_builder(
    datadir: impl Into<std::path::PathBuf>,
) -> eyre::Result<ArtificialPayloadBuilder<BenchDbProvider, EthEvmConfig>> {
    let client = make_bench_client(datadir)?;
    let evm_config = EthEvmConfig::mainnet();
    let builder_config = EthereumBuilderConfig::default();
    Ok(ArtificialPayloadBuilder::new(client, evm_config, builder_config))
}

fn make_bench_client(datadir: impl Into<std::path::PathBuf>) -> eyre::Result<BenchDbProvider> {
    let spec = ChainSpecBuilder::mainnet().build();

    let factory = EthereumNode::provider_factory_builder()
        .open_read_only(
            spec.into(),
            ReadOnlyConfig::from_datadir(datadir.into()),
        )?;

    let provider = factory.provider()?;
    Ok(provider)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtificialPayloadBuilder<Client, EvmConfig = EthEvmConfig> {
    client: Client,
    evm_config: EvmConfig,
    builder_config: EthereumBuilderConfig,
}

impl<Client, EvmConfig> ArtificialPayloadBuilder<Client, EvmConfig> {
    pub fn new(client: Client, evm_config: EvmConfig, builder_config: EthereumBuilderConfig) -> Self {
        Self { client, evm_config, builder_config }
    }
}

impl<Client, EvmConfig> PayloadBuilder for ArtificialPayloadBuilder<Client, EvmConfig> 
where 
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>  + BlockReader + TransactionsProvider + HeaderProvider<Header = AlloyHeader> + Clone,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        build_next_artificial_block(self.evm_config.clone(), self.client.clone(), self.builder_config.clone(), args)
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
    todo!()
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        todo!()
    }
}


fn fake_eth_attributes_from_parent<Client>(
    client: &Client,
    parent: &Header,
) -> Result<EthPayloadBuilderAttributes, PayloadBuilderError>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + BlockReader,

{
    let chain_spec = client.chain_spec();
    let parent_number = parent.number;
    let parent_timestamp = parent.timestamp;

    // naive: parent + 12 seconds
    let timestamp = parent_timestamp + 12;

    // coinbase: reuse parent beneficiary
    let suggested_fee_recipient: Address = parent.beneficiary;

    // prev_randao: use parent.mix_hash / parent.prev_randao equivalent
    let prev_randao: B256 = parent.mix_hash;

    // withdrawals: try to read from db for next block, else empty
    let withdrawals = client
        .withdrawals_by_number(parent_number + 1)?
        .map(|w| w.withdrawals)
        .unwrap_or_default();

    // parent beacon block root:
    // if cancun active, you may want to set to parent’s root or B256::ZERO
    let parent_beacon_block_root = None;

    Ok(EthPayloadBuilderAttributes::new(
        // id:
        // usually a U256 unique ID, we can just use parent_number+1 for bench
        U256::from(parent_number + 1),

        
    ))
}

pub fn build_from_block_number<EvmConfig, Client>(
    evm_config: EvmConfig,
    client: Client,
    builder_config: EthereumBuilderConfig,
    parent_block: u64,
) -> Result<EthBuiltPayload, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BlockReader
        + TransactionsProvider
        + HeaderProvider<Header = AlloyHeader>
        + Clone,
{
    // 1. get the parent header
    let parent_header = client
        .header_by_number(parent_block)?.unwrap();

    let attrs = fake_eth_attributes_from_parent(&client, &parent_header)?;
    
    let sealed_parent_header = SealedHeader::seal_slow(parent_header);

    let parent_header = Arc::new(sealed_parent_header);

    // 2. fake attributes

    // 3. wrap into the same shape your current code expects
    let build_args = BuildArguments::new(
        // cached_reads
        Default::default(),
        // config
        PayloadConfig { parent_header, attributes: attrs },
        // best_payload (we don't care, we just want to build)
        Default::default(),
        // cancel
        None,
    );

    // 4. call your existing function
    match build_next_artificial_block(evm_config, client, builder_config, build_args)? {
        reth_basic_payload_builder::BuildOutcome::Better { payload, .. } => Ok(payload),
        reth_basic_payload_builder::BuildOutcome::Aborted { .. } => {
            Err(PayloadBuilderError::other("artificial build aborted".into()))
        }
        reth_basic_payload_builder::BuildOutcome::Cancelled => {
            Err(PayloadBuilderError::other("artificial build cancelled".into()))
        }
        _ => {
            Err(PayloadBuilderError::other("artificial build returned unexpected outcome".into()))
        }
    }
}

pub fn build_next_artificial_block<EvmConfig, Client>(
    evm_config: EvmConfig,
    client: Client,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + BlockReader + TransactionsProvider {


    let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;
    let PayloadConfig { parent_header, attributes } = config;

    let state_provider = client.state_by_block_hash(parent_header.hash())?;
    let state = StateProviderDatabase::new(&state_provider);
    let mut db =
    State::builder().with_database(cached_reads.as_db_mut(state)).with_bundle_update().build();

    let mut builder = evm_config
    .builder_for_next_block(
        &mut db,
        &parent_header,
        NextBlockEnvAttributes {
            timestamp: attributes.timestamp(),
            suggested_fee_recipient: attributes.suggested_fee_recipient(),
            prev_randao: attributes.prev_randao(),
            gas_limit: builder_config.gas_limit(parent_header.gas_limit),
            parent_beacon_block_root: attributes.parent_beacon_block_root(),
            withdrawals: Some(attributes.withdrawals().clone()),
        },
    )
    .map_err(PayloadBuilderError::other)?;

    let chain_spec = client.chain_spec();

    debug!(target: "artificial_payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");

    let mut cumulative_gas_used = 0;
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit();
    let base_fee = builder.evm_mut().block().basefee();

    // initialize empty blob sidecars at first. If cancun is active then this will be populated by
    // blob sidecars if any.
    let mut blob_sidecars = BlobSidecars::Empty;

    let mut block_blob_count = 0;
    let mut block_transactions_rlp_length = 0;

    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);

    let max_blob_count =
    blob_params.as_ref().map(|params| params.max_blob_count).unwrap_or_default();

    let is_osaka = chain_spec.is_osaka_active_at_timestamp(attributes.timestamp);

    let indices = client.block_body_indices(parent_header.number)?;
    let last_tx_num = indices.unwrap().last_tx_num();

    info!(target: "artificial_payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, last_tx_num = last_tx_num, "the last tx num of the parent block is {last_tx_num}");

   
    todo!()
}

