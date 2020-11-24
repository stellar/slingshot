mod bc_annotations;
mod templates;
mod ws;

use super::config::Config;
use super::wallet;
use super::wallet_manager::WalletRef;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use std::collections::HashMap;

use tera::Tera;
use warp::Filter;
use warp::{filters::BoxedFilter, reply::Reply};

use crate::bc::BlockchainRef;

/// UI controller for each request.
#[derive(Clone, Debug)]
pub struct UI {
    /// Blockchain state machine
    bc: BlockchainRef,
    /// Wallet state
    wm: WalletRef,
    /// HTML templating engine
    tera: Arc<RwLock<Tera>>,
}

impl UI {
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
    pub async fn launch(config: Config, bc: BlockchainRef, wm: WalletRef) {
        let conf = &config.data.ui;
        let ui = UI {
            bc,
            wm,
            tera: templates::init_tera(),
        };

        eprintln!("UI:  http://{}", &conf.listen);
        warp::serve(ui.into_routes()).run(conf.listen).await;
    }

    /// Converts the UI controller into the warp filter.
    pub fn into_routes(self) -> BoxedFilter<(impl Reply,)> {
        let index = warp::get()
            .and(warp::path::end())
            .and(self.as_filter())
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

        index
            .or(ws_route)
            .or(static_route)
            .recover(move |err| {
                let ui = self.clone();
                async move { ui.handle_error(err).await }
            })
            .boxed()
    }

    /// Returns the reference to the blockchain.
    pub fn blockchain(&self) -> &BlockchainRef {
        &self.bc
    }
    /// Provides the UI object as a parameter to the Warp filter chain.
    pub fn as_filter(&self) -> impl Filter<Extract = (Self,), Error = Infallible> + Clone {
        let x = self.clone();
        warp::any().map(move || x.clone())
    }

    // /// Matches the request if the ledger is not initialized yet.
    // pub async fn require_uninitialized(self) -> Result<Self, warp::Rejection> {
    //     if !self.bc.read().await.is_initialized() {
    //         Ok(self)
    //     } else {
    //         Err(warp::reject::not_found())
    //     }
    // }

    // /// Matches the request if the ledger is not initialized yet.
    // pub async fn require_initialized(self) -> Result<Self, warp::Rejection> {
    //     if self.bc.read().await.is_initialized() {
    //         Ok(self)
    //     } else {
    //         Err(warp::reject::not_found())
    //     }
    // }

    /// Renders the template.
    pub fn render(&self, name: &'static str) -> Result<impl warp::Reply, Infallible> {
        // dummy context - load one from the UI object.
        let context = HashMap::<String, String>::new();
        let tera_renderer = self.tera.read().unwrap();
        let ctx = tera::Context::from_serialize(context).expect("context should be a JSON object");
        let html = tera_renderer
            .render(name, &ctx)
            .unwrap_or_else(|e| format!("Tera parse error: {}", e));
        Ok(warp::reply::html(html))
    }

    pub fn redirect_to_root(&self) -> Result<impl warp::Reply, Infallible> {
        Ok(warp::redirect(warp::http::Uri::from_static("/")))
    }

    pub async fn handle_error(&self, err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
        if err.is_not_found() {
            Ok(warp::reply::with_status(
                self.render("404.html")?,
                warp::http::StatusCode::NOT_FOUND,
            ))
        } else {
            eprintln!("unhandled rejection: {:?}", err);
            Ok(warp::reply::with_status(
                self.render("500.html")?,
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}
