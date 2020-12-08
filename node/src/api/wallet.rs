mod handlers;
mod requests;
mod responses;

use crate::api::types::Cursor;
use crate::wallet_manager::WalletRef;
use std::convert::Infallible;
use warp::filters::path::param;
use warp::{any, Filter};
use futures::future::NeverError;
use futures::{FutureExt, Future};
use crate::api::response::{ResponseResult, Response};
use crate::api::warp_utils::{handle2, handle1};

pub fn routes(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    new(wallet.clone())
        .or(balance(wallet.clone()))
        .or(txs(wallet.clone()))
        .or(address(wallet.clone()))
        .or(receiver(wallet.clone()))
        .or(buildtx(wallet))
}

fn new(
    wallet: WalletRef,
) -> impl Filter<Extract = (Response<responses::NewWallet>, ), Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "new")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::new))
}

fn balance(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "balance")
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle1(handlers::balance))
}

fn txs(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "txs")
        .and(query::<Cursor>())
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::txs))
}

fn address(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "address")
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle1(handlers::address))
}

fn receiver(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "receiver")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::receiver))
}

fn buildtx(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "buildtx")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::buildtx))
}

fn with_wallet(
    wallet: WalletRef,
) -> impl Filter<Extract = (WalletRef,), Error = Infallible> + Clone {
    any().map(move || wallet.clone())
}

#[cfg(test)]
mod wallet_tests {
    use super::*;

    use crate::wallet_manager::{WalletRef, WalletManager};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::config::Config;

    fn prepare_wallet() -> WalletRef {
        WalletManager::new(
            Config {
                data: Default::default(),
                path: Default::default()
            }
        ).unwrap()
    }

    async fn remove_wallet(wallet: WalletRef) {
        let mut manager = wallet.write().await;
        manager.clear_wallet();
    }

    #[tokio::test]
    async fn test_new() {
        let wallet = prepare_wallet();
        let routes = new(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request().path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 64],
                label: "test_label".to_string()
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }

    #[tokio::test]
    #[should_panic(expected = r#"Unwrap at err: ResponseError { code: 101, description: "Invalid address label" }"#)]
    async fn test_new_wrong_label() {
        let wallet = prepare_wallet();
        let routes = new(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request().path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 64],
                label: "invalid label".to_string()
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }

    #[tokio::test]
    #[should_panic(expected = r#"Unwrap at err: ResponseError { code: 102, description: "Invalid xpub" }"#)]
    async fn test_new_invalid_xpub() {
        let wallet = prepare_wallet();
        let routes = new(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request().path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 32],
                label: "test_label".to_string()
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }
}
