use std::error::Error;

use auth::Tokens;
use serde::Deserialize;

pub mod auth;

pub struct API {
    tokens: auth::Tokens
}

impl API {
    pub fn new(tokens: Tokens) -> API {
        API{tokens}
    }

    pub fn character(&self) -> Character {
        Character {
            tokens: self.tokens.clone()
        }
    } 
}

pub struct Character {
    tokens: auth::Tokens
}

impl Character {
    pub fn get(id: i32) -> Result<CharacterGetResponse, Box<dyn Error>> {
        let http = reqwest::blocking::Client::new();
        let resp = http.get(format!("https://esi.evetech.net/latest/characters/{}", id)).send()?;
        let body = resp.text()?;
        let body = serde_json::from_str(&body)?;
        Ok(body)
    }
}

#[derive(Deserialize)]
pub struct CharacterGetResponse {
    pub alliance_id: Option<i32>,
    pub birthday: chrono::DateTime<chrono::Utc>,
    pub bloodline_id: i32,
    pub corporation_id: i32,
    pub description: Option<String>,
    pub faction_id: Option<i32>,
    pub gender: String,
    pub name: String,
    pub race_id: i32,
    pub security_status: Option<f32>,
    pub title: Option<String>,
}

// pub fn add(left: usize, right: usize) -> usize {
//     left + right
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
