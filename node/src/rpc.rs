#![warn(missing_docs)]

use std::{fmt, sync::Arc};

use encointer_node_runtime::{
    opaque::Block, AccountId, Balance, Index, UncheckedExtrinsic,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_transaction_pool::TransactionPool;
use substrate_frame_rpc_system::AccountNonceApi;

/// Light client extra dependencies.
pub struct LightDeps<C, F, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Remote access to the blockchain (async).
    pub remote_blockchain: Arc<dyn sc_client_api::light::RemoteBlockchain<Block>>,
    /// Fetcher instance.
    pub fetcher: Arc<F>,
}


/// Full client dependencies.
pub struct FullDeps<C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
}

/// Instantiate all Full RPC extensions.
pub fn create_full<C, P, M>(deps: FullDeps<C, P>) -> jsonrpc_core::IoHandler<M>
    where
        C: ProvideRuntimeApi<Block>,
        C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
        C: Send + Sync + 'static,
        C::Api: AccountNonceApi<Block, AccountId, Index>,
        C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance, UncheckedExtrinsic>,
        <C::Api as sp_api::ApiErrorExt>::Error: fmt::Debug,
        P: TransactionPool + 'static,
        M: jsonrpc_core::Metadata + Default,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApi};
    use substrate_frame_rpc_system::{FullSystem, SystemApi};

    let mut io = jsonrpc_core::IoHandler::default();
    let FullDeps {
        client,
        pool,
    } = deps;

    io.extend_with(SystemApi::to_delegate(FullSystem::new(client.clone(), pool)));
    io.extend_with(TransactionPaymentApi::to_delegate(TransactionPayment::new(
        client.clone(),
    )));

    io
}

/// Instantiate all Light RPC extensions.
pub fn create_light<C, P, M, F>(deps: LightDeps<C, F, P>) -> jsonrpc_core::IoHandler<M>
    where
        C: HeaderBackend<Block>,
        C: Send + Sync + 'static,
        F: sc_client_api::light::Fetcher<Block> + 'static,
        P: TransactionPool + 'static,
        M: jsonrpc_core::Metadata + Default,
{
    use substrate_frame_rpc_system::{LightSystem, SystemApi};

    let LightDeps {
        client,
        pool,
        remote_blockchain,
        fetcher,
    } = deps;
    let mut io = jsonrpc_core::IoHandler::default();
    io.extend_with(SystemApi::<AccountId, Index>::to_delegate(LightSystem::new(
        client,
        remote_blockchain,
        fetcher,
        pool,
    )));

    io
}