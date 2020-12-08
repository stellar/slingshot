mod handlers;
mod requests;
mod responses;

use crate::api::response::{Response, ResponseResult};
use crate::api::types::Cursor;
use crate::api::warp_utils::{handle1, handle2};
use crate::wallet_manager::WalletRef;
use futures::future::NeverError;
use futures::{Future, FutureExt};
use std::convert::Infallible;
use warp::filters::path::param;
use warp::{any, Filter};

pub fn routes(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    let new = path!("v1" / "wallet" / "new")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet.clone()))
        .and_then(handle2(handlers::new));

    let balance = path!("v1" / "wallet" / "balance")
        .and(get())
        .and(with_wallet(wallet.clone()))
        .and_then(handle1(handlers::balance));

    let txs = path!("v1" / "wallet" / "txs")
        .and(query::<Cursor>())
        .and(get())
        .and(with_wallet(wallet.clone()))
        .and_then(handle2(handlers::txs));

    let address = path!("v1" / "wallet" / "address")
        .and(get())
        .and(with_wallet(wallet.clone()))
        .and_then(handle1(handlers::address));

    let receiver = path!("v1" / "wallet" / "receiver")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet.clone()))
        .and_then(handle2(handlers::receiver));

    let buildtx = path!("v1" / "wallet" / "buildtx")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet.clone()))
        .and_then(handle2(handlers::buildtx));

    new.or(balance).or(txs).or(address).or(receiver).or(buildtx)
}

fn with_wallet(
    wallet: WalletRef,
) -> impl Filter<Extract = (WalletRef,), Error = Infallible> + Clone {
    any().map(move || wallet.clone())
}
/*
TODO: there are no posibility to testing because impl warp::Reply not implement warp::test::inner::OneOrTuple
#[cfg(test)]
mod wallet_tests {
    use super::*;

    use crate::config::Config;
    use crate::wallet_manager::{WalletManager, WalletRef};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn prepare_wallet() -> WalletRef {
        WalletManager::new(Config {
            data: Default::default(),
            path: Default::default(),
        })
        .unwrap()
    }

    async fn remove_wallet(wallet: WalletRef) {
        let mut manager = wallet.write().await;
        manager.clear_wallet();
    }

    #[tokio::test]
    async fn test_new() {
        let wallet = prepare_wallet();
        let routes = routes(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request()
            .path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 64],
                label: "test_label".to_string(),
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }

    #[tokio::test]
    #[should_panic(
        expected = r#"Unwrap at err: ResponseError { code: 101, description: "Invalid address label" }"#
    )]
    async fn test_new_wrong_label() {
        let wallet = prepare_wallet();
        let routes = routes(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request()
            .path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 64],
                label: "invalid label".to_string(),
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }

    #[tokio::test]
    #[should_panic(
        expected = r#"Unwrap at err: ResponseError { code: 102, description: "Invalid xpub" }"#
    )]
    async fn test_new_invalid_xpub() {
        let wallet = prepare_wallet();
        let routes = routes(wallet.clone());

        let response: Response<responses::NewWallet> = warp::test::request()
            .path("/v1/wallet/new")
            .method("POST")
            .json(&requests::NewWallet {
                xpub: vec![0; 32],
                label: "test_label".to_string(),
            })
            .filter(&routes)
            .await
            .unwrap();

        remove_wallet(wallet).await;

        response.unwrap_ok();
    }
}*/
