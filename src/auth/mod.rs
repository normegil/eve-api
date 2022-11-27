use std::io;

use rand::Rng;
use base64::*;
use serde::Deserialize;
use sha2::Digest;

use self::http_server::CodeResponse;

mod http_server;

pub struct ApplicationAuthFlow {
    client_id: String,
    callback_url: String,
    scopes: Vec<Scope>,
    port: Option<u16>,
}

impl ApplicationAuthFlow {
    pub fn new(client_id: &str, callback_url: &str, scopes: Vec<Scope>) -> ApplicationAuthFlow {
        ApplicationAuthFlow{
            client_id: client_id.to_string(), 
            callback_url: callback_url.to_string(), 
            scopes: scopes,
            port: None, 
        }
    }

    pub fn with_listening_port(mut self, port: u16) -> ApplicationAuthFlow {
        self.port = Some(port);
        self
    }

    pub fn auth(&self) -> io::Result<()>{
        let (_, challenge_to_send) = generate_challenge();
        let code = self.request_code(&challenge_to_send)?;
        let tokens = request_tokens(&code, &self.client_id, &challenge_to_send)?;

        Ok(())
    }

    fn request_code(&self, challenge: &str) -> io::Result<String> {
        let generated_id = uuid::Uuid::new_v4().to_string();
        let scopes: Vec<String> = self.scopes.iter().map(|s| s.to_string()).collect();
        let scopes = scopes.join(" ");
        let url = format!(
            "https://login.eveonline.com/v2/oauth/authorize/?response_type=code&code_challenge_method=S256&client_id={client_id}&redirect_uri={callback_uri}&scope={scope}&code_challenge={challenge}&state={generated_id}",
            client_id=self.client_id,
            callback_uri=urlencoding::encode(&self.callback_url),
            scope=urlencoding::encode(&scopes),
            generated_id=generated_id,
            challenge=challenge,
        );

        if let Err(e) = open::that(url) {
            return Err(e);
        }

        let code = http_server::Server::new(self.port.unwrap_or(35795))
            .get_code()?;
        if generated_id.to_string() != code.state {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid returned state (expected:'{}';got:'{}')", generated_id, code.state)))
        }
        Ok(code.code)
    }

}

pub enum Scope {
    PublicData
}

impl Scope {
    fn to_string(&self) -> String {
        String::from(match self {
            PublicData => "publicData",
        })
    }
}

fn generate_challenge() -> (String, String) {
    let rand_byte_array = rand::thread_rng().gen::<[u8; 32]>();
    let base64_config = Config::new(CharacterSet::UrlSafe, false);
    let challenge = base64::encode_config(rand_byte_array, base64_config);

    let mut hasher = sha2::Sha256::new();
    hasher.update(&challenge);
    let hashed_challenge = hasher.finalize();
    let challenge_to_send = base64::encode_config(hashed_challenge, base64_config);
    (challenge, challenge_to_send)
}

fn request_tokens(code: &str, client_id: &str, challenge: &str) -> io::Result<AuthTokenResponseBody> {
    let client = reqwest::blocking::Client::new();
    let resp  = client
        .post("https://login.eveonline.com/v2/oauth/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Host", "login.eveonline.com")
        .body(format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}&code_verifier={challenge}", 
            code=code,
            client_id=client_id,
            challenge=challenge,
        ))
        .send();
    
    let resp = match resp {
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to get auth token: {}", e))),
        Ok(r) => r,
    };
    let body = match resp.text() {
        Ok(b) => b,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to read response body for auth token: {}", e))), 
    };

    match serde_json::from_str::<AuthTokenResponseBody>(&body) {
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error when trying to deserialize response body for auth token from json: {}", e))),
        Ok(b) => Ok(b), 
    }
}

#[derive(Deserialize)]
struct AuthTokenResponseBody {
    token_type: String,
    expires_in: i32,
    access_token: String,
    refresh_token: String,
}