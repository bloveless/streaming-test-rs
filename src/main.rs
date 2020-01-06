mod server;
mod encode;
mod oauth;

use std::env;
use std::result::Result;

use dotenv;

const REQUEST_TOKEN_URL: &str = "https://api.twitter.com/oauth/request_token";
const AUTH_URL: &str = "https://api.twitter.com/oauth/authorize";
const ACCESS_TOKEN_URL: &str = "https://api.twitter.com/oauth/access_token";
const REDIRECT_URL: &str = "http://127.0.0.1:3000/oauth_response";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenv::dotenv().ok();

    let oauth_consumer_key = env::var("CONSUMER_KEY").expect("CONSUMER_KEY was not found in the environment");
    let oauth_consumer_key = oauth_consumer_key.as_str();
    let oauth_consumer_secret = env::var("CONSUMER_SECRET").expect("CONSUMER_SECRET was not found in the environment");
    let oauth_consumer_secret = oauth_consumer_secret.as_str();

    let request_token = oauth::get_request_token(
        REQUEST_TOKEN_URL,
        oauth_consumer_key,
        oauth_consumer_secret,
        REDIRECT_URL
    ).await?;

    println!("Visit https://api.twitter.com/oauth/authorize?oauth_token={} to authorize this app", request_token);

    let (oauth_token, oauth_verifier) = oauth::block_and_wait_for_temp_access_token();

    println!("Received oauth_token: {} and oauth_verifier {}", oauth_token, oauth_verifier);

    let (oauth_access_token, oauth_access_token_secret, user_id, screen_name) = oauth::exchange_temp_access_tokens_for_access_token(
        ACCESS_TOKEN_URL,
        oauth_consumer_key,
        oauth_token.as_str(),
        oauth_verifier.as_str()
    ).await?;

    println!("OAuth Token: {}, OAuth Token Secret: {}, User ID: {}, Screen Name: {}", oauth_access_token, oauth_access_token_secret, user_id, screen_name);

    let filter_body = oauth::make_authorized_request(
        "GET",
        "https://api.twitter.com/1.1/statuses/home_timeline.json",
        oauth_consumer_key,
        oauth_consumer_secret,
        oauth_access_token.as_str(),
        oauth_access_token_secret.as_str(),
        vec![]
    ).await?;

    println!("Filter body: {}", filter_body);

    Ok(())
}


