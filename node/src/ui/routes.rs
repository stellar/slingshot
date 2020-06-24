use std::sync::Arc;

use warp::{filters::BoxedFilter, reply::Reply, Filter};

use super::ui_helpers::UI;
use super::ws;

/// Builds all routes
pub fn build(ui: UI) -> BoxedFilter<(impl Reply,)> {
    let welcome = warp::get()
        .and(warp::path::end())
        .and(ui.as_filter())
        .and_then(|ui: UI| ui.require_uninitialized())
        .and_then(|ui: UI| async move { ui.render("welcome.html") });

    let ledger_new = warp::get()
        .and(warp::path!("ledger" / "new"))
        .and(ui.as_filter())
        .and_then(|ui: UI| ui.require_uninitialized())
        .and_then(|ui: UI| async move {
            ui.blockchain().write().await.initialize();
            ui.redirect_to_root()
        });

    let ledger_connect_existing = warp::get()
        .and(warp::path!("ledger" / "connect"))
        .and(ui.as_filter())
        .and_then(|ui: UI| ui.require_uninitialized())
        .and_then(|ui: UI| async move { ui.render("404.html") });

    let index = warp::get()
        .and(warp::path::end())
        .and(ui.as_filter())
        .and_then(|ui: UI| ui.require_initialized())
        .and_then(|ui: UI| async move { ui.render("index.html") });

    let ws_pool = Arc::new(ws::WebsocketPool::default());
    let ws_route = warp::path("ws")
        .and(warp::any().map(move || ws_pool.clone()))
        .and(warp::ws())
        .map(|wspool: Arc<ws::WebsocketPool>, ws: warp::ws::Ws| {
            ws.on_upgrade(move |socket| wspool.add(socket))
        });

    // warp::header::headers_cloned()

    let static_route = warp::path("static").and(warp::fs::dir("static"));

    welcome
        .or(ledger_new)
        .or(ledger_connect_existing)
        .or(index)
        .or(ws_route)
        .or(static_route)
        .recover(move |err| {
            let ui = ui.clone();
            async move { ui.handle_error(err).await }
        })
        .boxed()
}
