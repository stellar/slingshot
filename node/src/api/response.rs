use warp::Reply;
use warp::reply::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct Response<T> {
    ok: bool,
    response: Option<T>,
    error: Option<ResponseError>
}

#[derive(Serialize)]
pub struct ResponseError {
    code: u16,
    description: String,
}

impl ResponseError {
    pub fn new(code: u16, description: impl Into<String>) -> Self {
        ResponseError { code, description: description.into() }
    }
}

impl<T> Response<T> {
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            response: Some(data),
            error: None,
        }
    }
    pub fn err(err: ResponseError) -> Self {
        Self {
            ok: false,
            response: None,
            error: Some(err),
        }
    }
}

impl<T: Serialize + Send> Reply for Response<T> {
    fn into_response(self) -> warp::reply::Response {
        warp::reply::json(&self).into_response()
    }
}

pub mod error {
    use crate::api::response::{Response, ResponseError};
    use crate::wallet::WalletError;

    pub fn cannot_delete_file<T>() -> Response<T> {
        Response::err(ResponseError::new(100, "Cannot delete file with wallet"))
    }
    pub fn invalid_address_label<T>() -> Response<T> {
        Response::err(ResponseError::new(101, "Invalid address label"))
    }
    pub fn invalid_xpub<T>() -> Response<T> {
        Response::err(ResponseError::new(101, "Invalid xpub"))
    }
    pub fn wallet_not_exists<T>() -> Response<T> {
        Response::err(ResponseError::new(103, "Wallet not exists"))
    }
    pub fn wallet_updating_error<T>() -> Response<T> {
        Response::err(ResponseError::new(104, "Something wrong when updating wallet"))
    }
    pub fn tx_building_error<T>() -> Response<T> {
        Response::err(ResponseError::new(105, "Something wrong when building tx"))
    }
    pub fn wallet_error<T>(error: WalletError) -> Response<T> {
        let code = match &error {
            WalletError::InsufficientFunds => 106,
            WalletError::XprvMismatch => 107,
            WalletError::AssetNotFound => 108,
            WalletError::AddressLabelMismatch => 109,
        };
        Response::err(ResponseError::new(code, error.to_string()))
    }
}
