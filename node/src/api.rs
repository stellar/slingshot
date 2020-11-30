pub(self) mod serde_utils;
mod data;
mod network;
mod wallet;

use std::net::SocketAddr;
use warp::Filter;

use crate::bc::BlockchainRef;
use crate::config::Config;
use crate::wallet_manager::WalletRef;

/// Launches the API server.
pub async fn launch(config: Config, bc: BlockchainRef, wallet: WalletRef) {
    let conf = &config.data.api;
    if conf.disabled {
        return;
    }
    let wallet_routes = wallet::routes();

    let not_found = warp::any()
        .map(|| warp::reply::with_status("Not found.", warp::http::StatusCode::NOT_FOUND));

    let routes = wallet_routes.or(not_found);

    eprintln!("API: http://{}", &conf.listen);
    warp::serve(routes).run(conf.listen).await;
}
