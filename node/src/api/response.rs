use serde::Serialize;
use warp::reply::Json;
use warp::Reply;

pub type ResponseResult<T> = Result<T, ResponseError>;

#[derive(Debug, Serialize)]
pub struct Response<T> {
    ok: bool,
    response: Option<T>,
    error: Option<ResponseError>,
}

#[derive(Debug, Serialize)]
pub struct ResponseError {
    code: u16,
    description: String,
}

impl ResponseError {
    pub fn new(code: u16, description: impl Into<String>) -> Self {
        ResponseError {
            code,
            description: description.into(),
        }
    }
}

impl<T> From<Result<T, ResponseError>> for Response<T> {
    fn from(res: Result<T, ResponseError>) -> Self {
        match res {
            Ok(t) => Response::ok(t),
            Err(e) => Response::err(e),
        }
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

#[cfg(test)]
impl<T> Response<T> {
    pub fn unwrap_ok(self) -> T {
        let Response {
            ok,
            response,
            error,
        } = self;
        if let Some(err) = error {
            panic!("Unwrap at err: {:?}", err);
        }
        response.unwrap()
    }
}
#[cfg(test)]
impl<T: std::fmt::Debug> Response<T> {
    pub fn unwrap_err(self) -> ResponseError {
        let Response {
            ok,
            response,
            error,
        } = self;
        if let Some(t) = response {
            panic!("Unwrap err at ok: {:?}", t);
        }
        error.unwrap()
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

    pub fn cannot_delete_file() -> ResponseError {
        ResponseError::new(100, "Cannot delete file with wallet")
    }
    pub fn invalid_address_label() -> ResponseError {
        ResponseError::new(101, "Invalid address label")
    }
    pub fn invalid_xpub() -> ResponseError {
        ResponseError::new(102, "Invalid xpub")
    }
    pub fn wallet_does_not_exist() -> ResponseError {
        ResponseError::new(103, "Wallet not exists")
    }
    pub fn wallet_updating_error() -> ResponseError {
        ResponseError::new(104, "Something wrong when updating wallet")
    }
    pub fn tx_building_error() -> ResponseError {
        ResponseError::new(105, "Something wrong when building tx")
    }
    pub fn wallet_error(error: WalletError) -> ResponseError {
        let code = match &error {
            WalletError::InsufficientFunds => 106,
            WalletError::XprvMismatch => 107,
            WalletError::AssetNotFound => 108,
            WalletError::AddressLabelMismatch => 109,
        };
        ResponseError::new(code, error.to_string())
    }
    pub fn invalid_cursor() -> ResponseError {
        ResponseError::new(110, "Something wrong when building tx")
    }
    pub fn tx_compute_error() -> ResponseError {
        ResponseError::new(111, "Something wrong when computing tx")
    }
}
