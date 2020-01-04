use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
// use std::convert::Infallible;
// use std::net::SocketAddr;

use dotenv;
use anyhow;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

// use hyper::{Body, Request, Response, Server};
// use hyper::service::{make_service_fn, service_fn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let client_id = env::var("CLIENT_ID").expect("CLIENT_ID was not found in the environment");
    let client_secret = env::var("CLIENT_SECRET").expect("CLIENT_SECRET was not found in the environment");

    println!("CID: {}, CS: {}", client_id, client_secret);

    let request_token_url = "https://api.twitter.com/oauth/request_token";
    let auth_url = "https://api.twitter.com/oauth/authorize";
    let token_url = "https://api.twitter.com/oauth/access_token";
    let redirect_url = "http://127.0.0.1:3000";
    let redirect_url_encoded = "http%3A%2F%2F127.0.0.1%3A3000%2Foauth%2Freceive";

    let rng = thread_rng();
    let auth_nonce: String = rng.sample_iter(Alphanumeric).take(50).collect();
    println!("Auth nonce: {}", auth_nonce);

    let oauth_signature = "";
    let oauth_signature_method = "HMAC-SHA1";
    let oauth_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    println!("timestamp: {}", oauth_timestamp);

    let params = [("oauth_consumer_key", client_id), ("oauth_callback", redirect_url_encoded.to_string())];
    let client = reqwest::Client::new();
    let res = client.post(request_token_url)
        .form(&params)
        .send()
        .await?
        .text()
        .await?;

    println!("Res: {:?}", res);

    Ok(())

    /*
    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // A `Service` is needed for every connection, so this
    // creates one from our `hello_world` function.
    let make_svc = make_service_fn(|_conn| async {
        // service_fn converts our function into a `Service`
        Ok::<_, Infallible>(service_fn(hello_world))
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    println!("Server listening on {}", addr.to_string());
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    */
}

/*
async fn hello_world(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World".into()))
}
*/
