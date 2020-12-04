mod dto;
mod network;
mod response;
pub(self) mod serde_utils;
mod wallet;
mod warp_utils;

use std::net::SocketAddr;
use warp::Filter;

use crate::bc::BlockchainRef;
use crate::config::Config;
use crate::wallet_manager::WalletRef;
use std::convert::Infallible;

/// Launches the API server.
pub async fn launch(config: Config, bc: BlockchainRef, wallet: WalletRef) {
    let conf = &config.data.api;
    if conf.disabled {
        return;
    }
    let routes = routes(bc, wallet);

    eprintln!("API: http://{}", &conf.listen);
    warp::serve(routes).run(conf.listen).await;
}

fn routes(bc: BlockchainRef, wallet: WalletRef) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
    let wallet_routes = wallet::routes(wallet);
    let network_routes = network::routes(bc);

    let not_found = warp::any()
        .map(|| warp::reply::with_status("Not found.", warp::http::StatusCode::NOT_FOUND));

    wallet_routes.or(network_routes).or(not_found)
}
