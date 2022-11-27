use std::io;

use rand::Rng;
use base64::*;
use sha2::Digest;

pub mod http_server;

pub struct ApplicationAuthFlow {
    client_id: String,
    callback_url: String,
    scopes: Vec<Scope>,
}

impl ApplicationAuthFlow {
    pub fn new(client_id: &str, callback_url: &str, scopes: Vec<Scope>) -> ApplicationAuthFlow {
        ApplicationAuthFlow{
            client_id: client_id.to_string(), 
            callback_url: callback_url.to_string(), 
            scopes: scopes
        }
    }

    // pub fn connect_temp(&self) -> io::Result<()>{
    //     let generated_id = uuid::Uuid::new_v4().to_string();
    //     let scopes: Vec<String> = self.scopes.iter().map(|s| s.to_string()).collect();
    //     let scopes = scopes.join(" ");

    //     let (_, challenge_to_send) = generate_challenge();

    //     let url = format!(
    //         "https://login.eveonline.com/v2/oauth/authorize/?response_type=code&code_challenge_method=S256&client_id={client_id}&redirect_uri={callback_uri}&scope={scope}&code_challenge={challenge}&state={generated_id}",
    //         client_id=self.client_id,
    //         callback_uri=urlencoding::encode(&self.callback_url),
    //         scope=urlencoding::encode(&scopes),
    //         generated_id=generated_id,
    //         challenge=challenge_to_send,
    //     );

    //     if let Err(e) = open::that(url) {
    //         return Err(e);
    //     }
        


    // }
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