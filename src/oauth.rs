use crate::encode::percent_encode;
use crate::server;

use anyhow;
use base64;

use std::result::Result;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use hmacsha1::hmac_sha1;

use url::form_urlencoded;

pub async fn get_request_token(
    url: &str,
    oauth_consumer_key: &str,
    oauth_consumer_secret: &str,
    callback_url: &str
) -> Result<String, anyhow::Error> {
    let redirect_url_encoded = percent_encode(callback_url);

    let request_token_body = make_authorized_request(
        "POST",
        url,
        oauth_consumer_key,
        oauth_consumer_secret,
        "",
        "",
        [("oauth_callback", redirect_url_encoded.as_str())].to_vec()
    ).await?;

    for (key, value) in form_urlencoded::parse(request_token_body.as_bytes()) {
        if key == "oauth_token" {
            return Ok(value);
        }
    }

    Err(anyhow::Error::msg("OAuth token was not found"))
}

pub fn block_and_wait_for_temp_access_token() -> (String, String) {
    let response = server::start_listening_and_wait_for_oauth_response().unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);

    req.parse(&response).unwrap();

    let path = req.path.unwrap();

    let mut current_url = String::from("http://dummy-url.com");
    current_url.push_str(path);

    let current_url = url::Url::parse(current_url.as_str()).expect("Unable to parse URL");

    let mut oauth_token: Option<String> = None;
    let mut oauth_verifier: Option<String> = None;
    for (key, value) in current_url.query_pairs().unwrap() {
        if key == "oauth_token" {
            oauth_token = Some(value);
        } else if key == "oauth_verifier" {
            oauth_verifier = Some(value);
        }
    }

    (oauth_token.unwrap(), oauth_verifier.unwrap())
}

pub async fn exchange_temp_access_tokens_for_access_token(
    access_token_url: &str,
    oauth_consumer_key: &str,
    oauth_token: &str,
    oauth_verifier: &str
) -> Result<(String, String, String, String), anyhow::Error> {
    let access_token_params = [
        ("oauth_consumer_key", oauth_consumer_key),
        ("oauth_token", oauth_token),
        ("oauth_verifier", oauth_verifier)
    ];

    let client = reqwest::Client::new();
    let access_token_request = client.post(access_token_url)
        .form(&access_token_params);

    let request_token_body = access_token_request.send().await?.text().await?;

    let mut oauth_access_token = None;
    let mut oauth_access_token_secret = None;
    let mut user_id = None;
    let mut screen_name = None;
    for (key, value) in form_urlencoded::parse(request_token_body.as_bytes()) {
        if key == "oauth_token" {
            oauth_access_token = Some(value);
        } else if key == "oauth_token_secret" {
            oauth_access_token_secret = Some(value);
        } else if key == "user_id" {
            user_id = Some(value);
        } else if key == "screen_name" {
            screen_name = Some(value);
        }
    }

    Ok((
        oauth_access_token.unwrap(),
        oauth_access_token_secret.unwrap(),
        user_id.unwrap(),
        screen_name.unwrap()
    ))
}

pub async fn make_authorized_request(
    method: &str,
    url: &str,
    oauth_consumer_key: &str,
    oauth_consumer_secret: &str,
    oauth_access_token: &str,
    oauth_access_token_secret: &str,
    parameters: Vec<(&str, &str)>,
) -> Result<String, anyhow::Error> {
    let rng = thread_rng();
    let auth_nonce: String = rng.sample_iter(Alphanumeric).take(50).collect();
    let oauth_nonce = auth_nonce.as_str();

    let oauth_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let oauth_timestamp= oauth_timestamp.as_str();

    let oauth_signature = generate_signature(
        "POST",
        url,
        oauth_consumer_key,
        oauth_consumer_secret,
        oauth_access_token,
        oauth_access_token_secret,
        oauth_nonce,
        oauth_timestamp,
        parameters.clone()
    );
    let oauth_signature = oauth_signature.as_str();

    let auth_header = generate_auth_header(
        oauth_consumer_key,
        oauth_nonce,
        oauth_signature,
        oauth_timestamp,
        oauth_access_token
    );

    let client = reqwest::Client::new();

    let request = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        _ => panic!("Invalid request method"),
    };

    let response = match request.header("Authorization", auth_header).form(&parameters).send().await {
        Ok(res) => res,
        Err(e) => return Err(anyhow::Error::new(e)),
    };

    println!("Response: {:?}", response);

    match response.text().await {
        Ok(body) => Ok(body),
        Err(e) => Err(anyhow::Error::new(e)),
    }
}

pub fn generate_auth_header(
    oauth_consumer_key: &str,
    oauth_nonce: &str,
    oauth_signature: &str,
    oauth_timestamp: &str,
    oauth_access_token: &str,
) -> String {
    let oauth_signature_method = "HMAC-SHA1";
    let oauth_version = "1.0";

    let mut auth_header = String::from("OAuth ");
    auth_header.push_str(format!("{}=\"{}\", ", "oauth_consumer_key", percent_encode(oauth_consumer_key)).as_str());
    auth_header.push_str(format!("{}=\"{}\", ", "oauth_nonce", percent_encode(oauth_nonce)).as_str());
    auth_header.push_str(format!("{}=\"{}\", ", "oauth_signature", percent_encode(oauth_signature)).as_str());
    auth_header.push_str(format!("{}=\"{}\", ", "oauth_signature_method", percent_encode(oauth_signature_method)).as_str());
    auth_header.push_str(format!("{}=\"{}\", ", "oauth_timestamp", percent_encode(oauth_timestamp)).as_str());

    if !oauth_access_token.is_empty() {
        auth_header.push_str(format!("{}=\"{}\", ", "oauth_token", percent_encode(oauth_access_token)).as_str());
    }

    auth_header.push_str(format!("{}=\"{}\"", "oauth_version", percent_encode(oauth_version)).as_str());

    auth_header
}

pub fn generate_signature(
    http_method: &str,
    url: &str,
    oauth_consumer_key: &str,
    oauth_consumer_secret: &str,
    oauth_access_token: &str,
    oauth_access_token_secret: &str,
    oauth_nonce: &str,
    oauth_timestamp: &str,
    parameters: Vec<(&str, &str)>
) -> String {
    let mut parameters_enc: Vec<String> = vec!();
    parameters_enc.push(format!("oauth_consumer_key={}", percent_encode(oauth_consumer_key)));

    if !oauth_access_token.is_empty() {
        parameters_enc.push(format!("oauth_token={}", percent_encode(oauth_access_token)));
    }

    parameters_enc.push(format!("oauth_nonce={}", percent_encode(oauth_nonce)));
    parameters_enc.push(format!("oauth_timestamp={}", percent_encode(oauth_timestamp)));
    parameters_enc.push("oauth_signature_method=HMAC-SHA1".to_string());
    parameters_enc.push("oauth_version=1.0".to_string());

    for p in parameters {
        parameters_enc.push(format!("{}={}", p.0, percent_encode(p.1)));
    }

    parameters_enc.sort_unstable();

    let signature_base_string: String = http_method.to_uppercase()
        + "&" + &percent_encode(url)
        + "&" + &percent_encode(&parameters_enc.join("&"));

    let mut signing_key = String::new();
    signing_key.push_str(oauth_consumer_secret);
    signing_key.push_str("&");
    signing_key.push_str(oauth_access_token_secret);

    let signed_request = hmac_sha1(signing_key.as_bytes(), signature_base_string.as_bytes());

    base64::encode(&signed_request)
}

#[test]
fn test_create_twitter_request_auth() {
    let http_method = "POST";
    let url = "https://api.twitter.com/1.1/statuses/update.json";
    let consumer_key = "xvz1evFS4wEEPTGEFPHBog";
    let client_secret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    let nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    let access_token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
    let access_token_secret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
    let timestamp = "1318622958";
    let parameters: Vec<(&str, &str)> = vec![
        ("status", "Hello Ladies + Gentlemen, a signed OAuth request!"),
        ("include_entities", "true"),
    ];

    let signature = generate_signature(
        http_method,
        url,
        consumer_key,
        client_secret,
        access_token,
        access_token_secret,
        nonce,
        timestamp,
        parameters
    );

    assert_eq!(signature, "hCtSmYh+iHYCEqBWrE7C7hYmtUk=".to_string());
}

#[test]
fn test_create_twitter_auth_header() {
    let oauth_consumer_key = "xvz1evFS4wEEPTGEFPHBog";
    let oauth_nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    let oauth_signature = "tnnArxj06cWHq44gCs1OSKk/jLY=";
    let oauth_timestamp = "1318622958";
    let oauth_token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";

    let auth_header = generate_auth_header(oauth_consumer_key, oauth_nonce, oauth_signature, oauth_timestamp, oauth_token);
    assert_eq!(auth_header, "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", oauth_version=\"1.0\"");
}

#[test]
fn test_create_twitter_auth_header_no_oauth_token() {
    let oauth_consumer_key = "xvz1evFS4wEEPTGEFPHBog";
    let oauth_nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    let oauth_signature = "tnnArxj06cWHq44gCs1OSKk/jLY=";
    let oauth_timestamp = "1318622958";
    let oauth_token = "";

    let auth_header = generate_auth_header(oauth_consumer_key, oauth_nonce, oauth_signature, oauth_timestamp, oauth_token);
    assert_eq!(auth_header, "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", oauth_version=\"1.0\"");
}

#[test]
fn test_full_sig_auth_header_process() {
    let oauth_consumer_key = "oEt67BQwKSdsrRcnn8SaeHmZU";
    let oauth_consumer_secret = "1P3cT1jOz4eOplElPgzA9IHXsli04WkZWy5yuJaKzb6GdCQfPp";

    let oauth_timestamp = "1578147081";
    let oauth_nonce="PQ6xJwmcWW3";

    let oauth_signature = generate_signature(
        "GET",
        "https://api.twitter.com/oauth/request_token",
        oauth_consumer_key,
        oauth_consumer_secret,
        "",
        "",
        oauth_nonce,
        oauth_timestamp,
        vec!()
    );

    let auth_header = generate_auth_header(
        oauth_consumer_key,
        oauth_nonce,
        oauth_signature.as_str(),
        oauth_timestamp,
        ""
    );

    assert_eq!(auth_header, "OAuth oauth_consumer_key=\"oEt67BQwKSdsrRcnn8SaeHmZU\", oauth_nonce=\"PQ6xJwmcWW3\", oauth_signature=\"YIOfjUMx6pu%2FdtA4XP5dJ5kXTsU%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1578147081\", oauth_version=\"1.0\"")
}

#[test]
fn test_from_lti_tools() {
    // http://lti.tools/oauth/
    let oauth_consumer_key = "dpf43f3p2l4k3l03";
    let oauth_consumer_secret = "kd94hf93k423kf44";
    let oauth_access_token = "nnch734d00sl2jdk";
    let oauth_access_token_secret = "pfkkdhi9sl3r4s00";

    let oauth_timestamp = "1191242096";
    let oauth_nonce = "kllo9940pd9333jh";

    let method = "GET";
    let url = "https://photos.example.net/photos";
    let params = vec![("size", "original"), ("file", "vacation.jpg")];

    let signature = generate_signature(
        method,
        url,
        oauth_consumer_key,
        oauth_consumer_secret,
        oauth_access_token,
        oauth_access_token_secret,
        oauth_nonce,
        oauth_timestamp,
        params
    );

    assert_eq!(signature, "/UeEmNUsboAh2ZZD7O92ECdXfr8=");
}


#[test]
fn test_real_request() {
    let oauth_consumer_key = "oEt67BQwKSdsrRcnn8SaeHmZU";
    let oauth_consumer_secret = "1P3cT1jOz4eOplElPgzA9IHXsli04WkZWy5yuJaKzb6GdCQfPp";
    let oauth_timestamp = "1578150721";
    let oauth_nonce = "l0ytGmoyJt5chDFGbKj4aOODHumpg8dcm5c7U2SCdZ0hFceH5E";

    let signature = generate_signature(
        "GET",
        "https://api.twitter.com/oauth/request_token",
        oauth_consumer_key,
        oauth_consumer_secret,
        "",
        "",
        oauth_nonce,
        oauth_timestamp,
        vec!()
    );

    assert_eq!(percent_encode(signature.as_str()), "YRWpxd9uruf2Ja7iDs%2F5lzV7x1M%3D");
}

#[test]
fn test_another_real_request() {
    let oauth_consumer_key = "oEt67BQwKSdsrRcnn8SaeHmZU";
    let oauth_consumer_secret = "1P3cT1jOz4eOplElPgzA9IHXsli04WkZWy5yuJaKzb6GdCQfPp";
    let oauth_timestamp = "1578151403";
    let oauth_nonce = "7MgtGXWQI2gkG2IwMuyUWEvoNDAahxYCRm33iCMTCi8f0gVEHm";

    let signature = generate_signature(
        "GET",
        "https://api.twitter.com/oauth/request_token",
        oauth_consumer_key,
        oauth_consumer_secret,
        "",
        "",
        oauth_nonce,
        oauth_timestamp,
        vec!()
    );

    assert_eq!(percent_encode(signature.as_str()), "huiIz4BadEDLUcse2qSmEanjZsg%3D");
}