use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Response, StatusCode};
use hyper::body::Bytes;

pub(crate) fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
pub(crate) fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn forge_res(
    msg: &'static str,
    status_code: StatusCode,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full(msg));
    *resp.status_mut() = status_code;
    resp
}
