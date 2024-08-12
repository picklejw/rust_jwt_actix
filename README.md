# rust-jtw-actix
A JWT Token authentication wrapper service for securing routes in Actix applications

Just a quick throw it out there JWT implementation, below is the example case I have implemented this in my own code.

```
use actix_web::{
  middleware::{ Logger, NormalizePath, TrailingSlash },
  web::Data,
  http::header,
  App,
  HttpServer,
};
use rust_jwt_actix::jwt_middleware; // This is the JWT lib import, just follow the code.

pub fn build_auth_routes() -> Scope {
  // web
  //   ::scope("/api/auth")
  //   .route("/signup", web::post().to(signup))
  //   .route("/login", web::post().to(login))
}

pub fn build_user_routes() -> Scope {
  // web
  //   ::scope("/api/user")
  //   .route("/echo", web::get().to(echo))
}

use actix_web_lab::middleware::from_fn;
HttpServer::new(move || {
  let auth_scope = build_auth_routes();
  let user_scope = build_user_routes();
  let auth = from_fn(jwt_middleware);
  App::new()
    .wrap(NormalizePath::new(TrailingSlash::Trim))
    .wrap(Logger::default())
    // .wrap(cors_opts)
    .service(auth_scope)
    .service(user_scope.wrap(auth))
});

```

This implements a function that will run on protected routes "user_scope". 

You can use this bit of code for generating new tokens to be validated internally and setting them on response via cookies:
```
  let n_tokens = AUTH_STATE.write()
    .expect("Unable to write to AUTH_STATE")
    .renew_tokens_by_id(&user.username.clone().expect("Could not find username on /signup"));
  let at_cookie = CookieBuilder::new(
    "access_token",
    n_tokens.access_token.expect("Could not get new access token to set on signup")
  )
    .path("/")
    .http_only(true)
    .finish();
  let rt_cookie = CookieBuilder::new(
    "refresh_token",
    n_tokens.refresh_token.expect("Could not get new refresh token to set on login")
  )
    .path("/")
    .http_only(true)
    .finish();

  HttpResponse::Ok().cookie(at_cookie).cookie(rt_cookie).json(AuthReply {
    error: None,
    success: true,
    user,
  })
```

Currently there is no way to invalidate tokens, clear from current cache when they expire and user has not renewed their session for sometime or efficiently check tokens without locking the data causing performance issues in a production environment.

This is in use for a personal project because of my need for authentication on a internal network, I'll come back to this and update to fix these issues.


