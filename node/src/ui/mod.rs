mod routes;
mod templates;
mod ui_helpers;
mod bc_annotations;
mod ws;

use super::wallet;

use std::net::SocketAddr;
use std::time::SystemTime;

use self::ui_helpers::UI;
use crate::bc::BlockchainRef;

/// Launches the UI server.
/// Takes a receiving channel as a parameter that receives
///
/// /               -> General network stats: chain state, mempool, connected peers, accounts.
/// /blocks         -> List of blocks
/// /blocks/:height -> View into a block
/// /mempool        -> List mempool txs
/// /tx/:id         -> Tx details and status (confirmed, mempool, dropped)
///
/// /ws             -> websocket notifications
pub async fn launch(addr: SocketAddr, bc: BlockchainRef) {
    let ui = UI::new(bc);

    eprintln!("UI:  http://{}", &addr);
    warp::serve(routes::build(ui)).run(addr).await;
}

/// Returns the current system time.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime should work")
        .as_millis() as u64
}
