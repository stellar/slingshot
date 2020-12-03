use futures::{future::NeverError, Future, FutureExt};
use crate::api::response::{Response, ResponseResult};

// Combinator Fn(A) -> impl Future<Output = ResponseResult<T>> into Fn(A) -> impl TryFuture<Output = Response<T>, Error = Infallible>
fn handle1<F, A, Fut, T>(f: F) -> impl Fn(A) -> NeverError<futures_util::future::MapInto<Fut, Response<T>>> + Clone
where
    F: Fn(A) -> Fut + 'static + Clone,
    Fut: Future<Output = ResponseResult<T>>,
{
    move |a| f(a).map_into().never_error()
}

// Combinator Fn(A, B) -> impl Future<Output = ResponseResult<T>> into Fn(A, B) -> impl TryFuture<Output = Response<T>, Error = Infallible>
fn handle2<F, A, B, Fut, T>(f: F) -> impl Fn(A, B) -> NeverError<futures_util::future::MapInto<Fut, Response<T>>> + Clone
where
    F: Fn(A, B) -> Fut + 'static + Clone,
    Fut: Future<Output = ResponseResult<T>>,
{
    move |a, b| f(a, b).map_into().never_error()
}
