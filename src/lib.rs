use actix_web::{
  body::MessageBody,
  dev::{ ServiceRequest, ServiceResponse },
  Error,
  error::{ ErrorUnauthorized, ErrorInternalServerError },
};
use actix_web_lab::middleware::Next;
use actix_web::cookie::CookieBuilder;

use std::time::{ SystemTime, UNIX_EPOCH };
use uuid::Uuid;
use base64::prelude::*;
use lazy_static::lazy_static;
use std::collections::{ HashSet, HashMap };
use std::sync::{ RwLock, Arc };

#[derive(Eq, Hash, PartialEq)]
pub enum TokenType {
  AccessToken = 0,
  RefreshToken = 1,
}

impl ToString for TokenType {
  fn to_string(&self) -> String {
    match *self {
      TokenType::AccessToken => "AccessToken".to_string(),
      TokenType::RefreshToken => "RefreshToken".to_string(),
    }
  }
}

#[derive(Clone)]
pub struct Tokens {
  pub access_token: Option<String>,
  pub refresh_token: Option<String>,
}
pub struct AuthState {
  valid_tokens: HashMap<String, Tokens>,
  stale_access_tokens: HashSet<String>, // move access_tokens to stale_access_tokens, if it gets picked up on request invalidate new access_token and refresh_token
}

pub struct ParsedCookie {
  uid: String,
  exp_date: String,
  uuid: String,
}

impl AuthState {
  fn new() -> Self {
    AuthState {
      valid_tokens: HashMap::new(),
      stale_access_tokens: HashSet::new(),
    }
  }

  fn make_new_token(id: &str, type_id: TokenType) -> Option<String> {
    let one_hour = 3600;
    let one_min = 60;
    let current_time = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("Time went backwards")
      .as_secs();

    let mut add_time = 0;
    // TODO: when moving to lib we need a way for users to configure this value
    if type_id == TokenType::AccessToken {
      add_time = one_min * 2;
    }
    if type_id == TokenType::RefreshToken {
      add_time = one_hour * 168; // one week
    }

    encode_b64(
      id.to_owned() +
        "~" +
        &(&current_time + add_time).to_string() +
        "~" +
        type_id.to_string().as_str() +
        "~" +
        &Uuid::new_v4().to_string()
    )
  }

  fn parse_token(token_str: &str) -> ParsedCookie {
    let decoded = decode_b64(token_str).expect("Could not decode token to readable string");
    let parts: Vec<_> = decoded.split("~").collect();
    ParsedCookie {
      uid: parts.get(0).expect("Could not get uid for parse_cookie").to_string(),
      exp_date: parts.get(1).expect("Could not get exp_date for parse_cookie").to_string(),
      uuid: parts.get(2).expect("Could not get uuid for parse_cookie").to_string(),
    }
  }

  // TODO: this validate auth is not very efficiant for many reads to write ratio. Need to break out validate auth and pub fn() for setting new tokens
  // for safely writing to this state we use RwLock, but we always call .write() when we are checking for tokens but not always updating tokens
  pub fn validate_auth(&mut self, current_request: &ServiceRequest) -> Result<Tokens, String> {
    if let Some(req_a_cookie) = current_request.cookie("access_token") {
      let req_a_token = req_a_cookie.value();
      let req_r_cookie = current_request
        .cookie("refresh_token")
        .expect("Could not get refresh_token on validating expired access_token");
      let req_r_token = req_r_cookie.value();
      let a_parsed = AuthState::parse_token(req_a_token);

      if let Some(uid_dat) = self.valid_tokens.get_mut(&a_parsed.uid) {
        let current_time = SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_millis()
          .to_string();

        if current_time > a_parsed.exp_date {
          // access_token expired
          if
            &req_r_token ==
            uid_dat.refresh_token.as_ref().expect("saved tokens did not have refresh_token")
          {
            let r_parsed = AuthState::parse_token(req_r_token);
            if current_time > r_parsed.exp_date {
              // expired refresh_token
              Err("Refresh Token has expired, you need to login.".to_string())
            } else {
              Ok(Tokens {
                access_token: Self::make_new_token(&a_parsed.uid, TokenType::AccessToken),
                refresh_token: Some(req_r_token.to_string()),
              })
            }
          } else {
            Err(
              "Refresh token does not match, cannot generate new tokens... don't know why this would happen".to_string()
            )
          }
        } else {
          // access_token found and is good

          Ok(Tokens {
            access_token: None,
            refresh_token: None,
          })
        }
      } else {
        Err("We can't find you, please login.".to_string())
      }
    } else {
      Err("No access token, you need to login.".to_string()) // no access token
    }
  }

  pub fn renew_tokens_by_id(&mut self, uid: &str) -> Tokens {
    let n_tokens = Tokens {
      access_token: Self::make_new_token(uid, TokenType::AccessToken),
      refresh_token: Self::make_new_token(uid, TokenType::RefreshToken),
    };

    if let Some(uid_dat) = self.valid_tokens.get_mut(uid) {
      self.stale_access_tokens.insert(
        uid_dat.access_token
          .clone()
          .expect("Could not add expiring access_token to stale_access_tokens")
          .to_string()
      );
      *uid_dat = n_tokens.clone();
    } else {
      self.valid_tokens.insert(uid.to_string(), n_tokens.clone());
    }

    n_tokens
  }

  pub fn remove_tokens_by_id(&mut self, uid: &str) -> bool {
    self.valid_tokens.remove(uid);
    true
  }

  fn check_and_clear_all_expired_tokens(&mut self) {
    // clear tokens only if expiration is older then 2 hours from now
    // so stale_access_tokens is more reliable
  }
}

pub fn decode_b64(b64_string: &str) -> Option<String> {
  let decoded = BASE64_STANDARD.decode(b64_string).expect("Decoding for auth failed");
  Some(String::from_utf8(decoded).expect("Could not conver b64 decode to string"))
}

pub fn encode_b64(b64_string: String) -> Option<String> {
  Some(BASE64_STANDARD.encode(b64_string))
}

lazy_static! {
  pub static ref AUTH_STATE: Arc<RwLock<AuthState>> = Arc::new(RwLock::new(AuthState::new()));
}

pub async fn jwt_middleware<T>(
  req: ServiceRequest,
  next: Next<T>
) -> Result<ServiceResponse<T>, Error>
  where T: MessageBody
{
  match AUTH_STATE.write() {
    Ok(mut mut_auth_state) => {
      match mut_auth_state.validate_auth(&req) {
        Ok(cookies) => {
          let mut res = next.call(req).await?;

          if cookies.access_token != None {
            let at_cookie = CookieBuilder::new(
              "access_token",
              cookies.access_token.expect("Could not set access token to cookie")
            )
              .path("/")
              .http_only(true)
              .finish();
            let rt_cookie = CookieBuilder::new(
              "refresh_token",
              cookies.refresh_token.expect("Could not set refresh token to cookie")
            )
              .path("/")
              .http_only(true)
              .finish();
            let res_mut = res.response_mut();
            res_mut.add_cookie(&at_cookie).expect("Could not add cookie: at");
            res_mut.add_cookie(&rt_cookie).expect("Could not add cookie: rt");
          }

          Ok(res)
        }
        Err(err_msg) => {
          Err(ErrorUnauthorized(format!("Invalid token: {}", err_msg).to_string()))?
        } // Handle poisoned lock
      }
    }
    Err(lock_err) => {
      Err(
        ErrorInternalServerError(
          format!("Internal Error Occured, PANIC NOW!: {}", "err_msg").to_string()
        )
      )?
    }
  }
}
