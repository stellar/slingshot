use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use tera::Tera;
use warp::Filter;

use super::templates;
use crate::bc::BlockchainRef;

/// UI controller for each request.
#[derive(Clone, Debug)]
pub struct UI {
    bc: BlockchainRef,
    tera: Arc<RwLock<Tera>>,
}

impl UI {
    pub fn new(bc: BlockchainRef) -> Self {
        Self {
            bc,
            tera: templates::init_tera(),
        }
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

    /// Matches the request if the ledger is not initialized yet.
    pub async fn require_uninitialized(self) -> Result<Self, warp::Rejection> {
        if !self.bc.read().await.initialized() {
            Ok(self)
        } else {
            Err(warp::reject::not_found())
        }
    }

    /// Matches the request if the ledger is not initialized yet.
    pub async fn require_initialized(self) -> Result<Self, warp::Rejection> {
        if self.bc.read().await.initialized() {
            Ok(self)
        } else {
            Err(warp::reject::not_found())
        }
    }

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
