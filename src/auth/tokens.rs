use std::{io};

use jsonwebtoken::{Validation, DecodingKey, errors::ErrorKind};
use reqwest::{Error};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access: AccessToken,
    pub refresh: RefreshToken
}

impl Tokens {
    pub fn refresh(&self) -> io::Result<Tokens> {
        let http = reqwest::blocking::Client::new();
        let resp = http.post("https://login.eveonline.com/v2/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Host", "login.eveonline.com")
            .body(format!(
                "grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}",
                refresh_token=self.refresh.token,
                client_id=self.refresh.client_id,
            ))
            .send();
        
        handle_token_response(resp, &self.refresh.client_id)
    }
}

#[derive(Debug, Clone)]
pub struct AccessToken(String);

impl AccessToken {
    fn validate(&self) -> Option<io::Error> {
        let key = match AuthTokenKey::request() {
            Err(e) => return Some(e),
            Ok(k) => k,
        };

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["EVE Online"]);
        match jsonwebtoken::decode::<AccessTokenClaims>(&self.0, &DecodingKey::from_secret(key.n.as_bytes()), &validation) {
            Ok(decoded_token) => {
                if decoded_token.claims.iss != "login.eveonline.com" || decoded_token.claims.iss != "https://login.eveonline.com" {
                    return Some(io::Error::new(io::ErrorKind::Other, format!("Invalid issuer: {}", decoded_token.claims.iss)))
                }
            },
            Err(e) => match e.kind() {
                ErrorKind::InvalidToken => return Some(io::Error::new(io::ErrorKind::Other, format!("Invalid token: {}", e))),
                ErrorKind::InvalidAudience => return Some(io::Error::new(io::ErrorKind::Other, format!("Invalid audience: {}", e))),
                _ => return Some(io::Error::new(io::ErrorKind::Other, format!("Unknown error when validating access token: {}", e))),
            },
        };
        None
    }
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    token: String,
    client_id: String   
}

impl RefreshToken {
    fn new(token: &str, client_id: &str) -> RefreshToken {
        RefreshToken { token: token.to_string(), client_id: client_id.to_string() }
    }
}

pub fn request_new(authentication_code: &str, client_id: &str, challenge: &str) -> io::Result<Tokens> {
    let http = reqwest::blocking::Client::new();
    let resp  = http
        .post("https://login.eveonline.com/v2/oauth/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Host", "login.eveonline.com")
        .body(format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}&code_verifier={challenge}", 
            code=authentication_code,
            client_id=client_id,
            challenge=challenge,
        ))
        .send();
    
    handle_token_response(resp, client_id)
}

fn handle_token_response(resp: Result<reqwest::blocking::Response, Error>, client_id: &str) -> io::Result<Tokens> {
    let resp = match resp {
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to get auth token: {}", e))),
        Ok(r) => r,
    };
    let body = match resp.text() {
        Ok(b) => b,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to read response body for auth token: {}", e))), 
    };
    let body = match serde_json::from_str::<AuthTokenResponseBody>(&body) {
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to deserialize response body for auth token from json: {}", e))),
        Ok(b) => b, 
    };

    let access_token = AccessToken(body.access_token);
    if let Some(e) = access_token.validate() {
        return Err(e);
    }

    Ok(Tokens { access: access_token, refresh: RefreshToken::new(&body.refresh_token, client_id) })
}

#[derive(Deserialize)]
struct AuthTokenResponseBody {
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
struct AuthTokenKeyResponseBody {
    keys: Vec<AuthTokenKey>
}

#[derive(Deserialize, Debug, Clone)]
struct AuthTokenKey {
    kid: String,
    n: String
}

impl AuthTokenKey {
    fn request() -> io::Result<AuthTokenKey> {
        let cli = reqwest::blocking::Client::new();
        let resp = cli.get("https://login.eveonline.com/oauth/jwks").send();
        let resp = match resp {
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to get auth token key for validation: {}", e))),
            Ok(r) => r,
        };
        let body = match resp.text() {
            Ok(b) => b,
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to read response body for auth token key for validation: {}", e))), 
        };

        let key = match serde_json::from_str::<AuthTokenKeyResponseBody>(&body) {
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to deserialize response body for auth token from json: {}", e))),
            Ok(b) => {
                let k = b.keys.iter().find(|b| b.kid == "JWT-Signature-Key");
                match k {
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("No key found: {:?}", b))),
                    Some(k) => k.clone(),
                }
            }, 
        };
        Ok(key)
    }
}

#[derive(Deserialize)]
struct AccessTokenClaims {
    iss: String,
}