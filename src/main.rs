mod helpers;

use crate::helpers::{empty, forge_res};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::borrow::Cow;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use url_encoded_data::UrlEncodedData;

#[derive(Debug)]
struct Contact<'a> {
    name: &'a str,
    email: &'a str,
    object: &'a str,
    message: &'a str,
}

async fn insert_contact(contact: Contact<'_>) -> Result<(), String> {
    let key = env::var("NOTION_API_KEY").map_err(|err| err.to_string())?;
    let page_id = env::var("CONTACT_DATABASE_ID").map_err(|err| err.to_string())?;
    let json_payload = format!(
        r#"{{
    "parent": {{
        "type": "database_id",
        "database_id": "{page_id}"
    }},
    "properties": {{
        "Nom": {{
            "id": "title",
            "type": "title",
            "title": [
                {{
                    "type": "text",
                    "text": {{
                        "content": "{}"
                    }}
                }}
            ]
        }},
        "Email": {{
            "rich_text": [
                {{
                    "type": "text",
                    "text": {{
                        "content": "{}"
                    }}
                }}
            ]
        }},
        "Objet": {{
            "type": "rich_text",
            "rich_text": [
                {{
                    "type": "text",
                    "text": {{
                        "content": "{}"
                    }}
                }}
            ]
        }},
        "Message": {{
            "type": "rich_text",
            "rich_text": [
                {{
                    "type": "text",
                    "text": {{
                        "content": "{}"
                    }}
                }}
            ]
        }}
    }}
}}"#,
        contact.name, contact.email, contact.object, contact.message
    );
    let safe_payload = html_escape::encode_text(&json_payload).to_string();
    let client = reqwest::Client::new();
    let res = client
        .post("https://api.notion.com/v1/pages")
        .header("Content-Type", "application/json")
        .header("Notion-Version", "2022-06-28")
        .header("Authorization", format!("Bearer {key}"))
        .body(safe_payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if res.status() == 200 {
        Ok(())
    } else {
        Err(String::from("unknown error"))
    }
}

async fn handle_contact(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, String> {
    let max = request.body().size_hint().upper().unwrap_or(u64::MAX);
    if max > 1024 * 64 {
        return Ok(forge_res("Body too big.", StatusCode::PAYLOAD_TOO_LARGE));
    }
    let (_, body) = request.into_parts();
    let whole_body = body.collect().await.map_err(|e| e.to_string())?;
    return match std::str::from_utf8(&whole_body.to_bytes()) {
        Ok(whole_body_to_str) => {
            let encoded_data = UrlEncodedData::from(whole_body_to_str);
            let raw_data = encoded_data.as_map_of_single_key_to_first_occurrence_value();
            if raw_data.len() != 4 {
                return Ok(forge_res("Bad request (1).", StatusCode::BAD_REQUEST));
            }
            match (
                raw_data
                    .get(&Cow::Borrowed("name"))
                    .map(std::borrow::ToOwned::to_owned),
                raw_data
                    .get(&Cow::Borrowed("email"))
                    .map(std::borrow::ToOwned::to_owned),
                raw_data
                    .get(&Cow::Borrowed("object"))
                    .map(std::borrow::ToOwned::to_owned),
                raw_data
                    .get(&Cow::Borrowed("message"))
                    .map(std::borrow::ToOwned::to_owned),
            ) {
                (Some(name), Some(email), Some(object), Some(message)) => {
                    let contact = Contact {
                        name,
                        email,
                        object,
                        message,
                    };
                    let response = Response::builder()
                        .status(200)
                        .header("Access-Control-Allow-Origin", "https://ike.icu")
                        .body(empty())
                        .map_err(|err| err.to_string())?;

                    match insert_contact(contact).await {
                        Ok(()) => Ok(response),
                        Err(e) => {
                            eprintln!("[crash] Unknown error - {e:?}");
                            Ok(forge_res(
                                "Internal server error",
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ))
                        }
                    }
                }
                _ => Ok(forge_res("Bad request. (2)", StatusCode::BAD_REQUEST)),
            }
        }
        Err(e) => {
            eprintln!("{e:?}");
            Ok(forge_res(
                "Internal server error.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    };
}

async fn handle_request(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, String> {
    match (request.method(), request.uri().path()) {
        (&Method::POST, "/contact") => match handle_contact(request).await {
            Ok(res) => Ok(res),
            Err(e) => {
                eprintln!("{e:?}");

                Ok(forge_res(
                    "Internal server error.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        },
        _ => Ok(forge_res("Not Found.", StatusCode::NOT_FOUND)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port_env = env::var("PORT");
    let port = port_env
        .unwrap_or_else(|_| String::from("3000"))
        .parse::<u16>()
        .unwrap_or_else(|_| 3000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    println!("Running on port {port}");
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                println!("Error serving connection: {err:?}");
            }
        });
    }
}
