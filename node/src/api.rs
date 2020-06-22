use std::net::SocketAddr;
use warp::Filter;

use crate::bc::BlockchainRef;

/// Launches the API server.
pub async fn launch(addr: SocketAddr, bc: BlockchainRef) {
    let echo =
        warp::path!("v1" / "echo" / String).map(|thingy| format!("API v1 echo: {}!", thingy));

    let not_found = warp::any()
        .map(|| warp::reply::with_status("Not found.", warp::http::StatusCode::NOT_FOUND));

    let routes = echo.or(not_found);

    eprintln!("API: http://{}", &addr);
    warp::serve(routes).run(addr).await;
}
