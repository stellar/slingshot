use serde::Serialize;
use warp::reply::Json;
use warp::Reply;

pub type ResponseResult<T> = Result<T, ResponseError>;

#[derive(Serialize)]
pub struct Response<T> {
    ok: bool,
    response: Option<T>,
    error: Option<ResponseError>,
}

#[derive(Serialize)]
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
            Err(e) => Response::err(e)
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
        ResponseError::new(101, "Invalid xpub")
    }
    pub fn wallet_not_exists() -> ResponseError {
        ResponseError::new(103, "Wallet not exists")
    }
    pub fn wallet_updating_error() -> ResponseError {
        ResponseError::new(
            104,
            "Something wrong when updating wallet",
        )
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
}
