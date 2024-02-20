use std::borrow::Cow;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Body, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use url_encoded_data::UrlEncodedData;

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Debug)]
struct Contact<'a> {
    name: &'a str,
    email: &'a str,
    object: &'a str,
    message: &'a str,
}

fn forge_res(msg: &str, status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full(msg));
    *resp.status_mut() = status_code;
    return resp;
}

async fn handle_contact(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let max = request.body().size_hint().upper().unwrap_or(u64::MAX);
    if max > 1024 * 64 {
        return Ok(forge_res("Body too big.", StatusCode::PAYLOAD_TOO_LARGE));
    }

    let whole_body = request.collect().await?.to_bytes();
    match std::str::from_utf8(&whole_body) {
        Ok(whole_body_to_str) => {
            let encoded_data = UrlEncodedData::from(whole_body_to_str);
            let raw_data = encoded_data.as_map_of_single_key_to_first_occurrence_value();
            if raw_data.len() != 4 {
                return Ok(forge_res("Bad request.", StatusCode::BAD_REQUEST));
            }
            match (
                raw_data
                    .get(&Cow::Borrowed("name"))
                    .map(|cow| cow.to_owned()),
                raw_data
                    .get(&Cow::Borrowed("email"))
                    .map(|cow| cow.to_owned()),
                raw_data
                    .get(&Cow::Borrowed("object"))
                    .map(|cow| cow.to_owned()),
                raw_data
                    .get(&Cow::Borrowed("message"))
                    .map(|cow| cow.to_owned()),
            ) {
                (Some(name), Some(email), Some(object), Some(message)) => {
                    let contact = Contact {
                        name,
                        email,
                        object,
                        message,
                    };
                    println!("{contact:?}");
                    Ok(Response::new(full("Ok.")))
                }
                _ => return Ok(forge_res("Bad request.", StatusCode::BAD_REQUEST)),
            }
        }
        Err(e) => {
            eprintln!("{:?}", e);
            return Ok(forge_res(
                "Internal server error.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}

async fn handle_request(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (request.method(), request.uri().path()) {
        (&Method::POST, "/contact") => handle_contact(request).await,
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
