use std::{io, fmt::Display};

use rand::Rng;
use base64::*;
use sha2::Digest;

mod http_server;
mod tokens;

pub struct Authenticator {
    client_id: String,
    callback_url: String,
    scopes: Vec<Scope>,
    port: Option<u16>,
}

impl Authenticator {
    pub fn new(client_id: &str, callback_url: &str, scopes: Vec<Scope>) -> Authenticator {
        Authenticator{
            client_id: client_id.to_string(), 
            callback_url: callback_url.to_string(), 
            scopes,
            port: None, 
        }
    }

    pub fn with_listening_port(mut self, port: u16) -> Authenticator {
        self.port = Some(port);
        self
    }

    pub fn authenticate(&self) -> io::Result<tokens::Tokens>{
        let (_, challenge_to_send) = generate_challenge();
        let code = self.request_code(&challenge_to_send)?;
        
        tokens::request_new(&code, &self.client_id, &challenge_to_send)
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
        if generated_id != code.state {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid returned state (expected:'{}';got:'{}')", generated_id, code.state)))
        }
        Ok(code.code)
    }

}

pub enum Scope {
    PublicData
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Scope::PublicData => "publicData",
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