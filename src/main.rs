use async_trait::async_trait;
use axum::{
    extract::{
        rejection::TypedHeaderRejectionReason, FromRef, FromRequestParts, Query, State, TypedHeader,
    },
    http::request::Parts,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, RequestPartsExt, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use headers::HeaderMap;
use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::{
    header::{self, SET_COOKIE},
    StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

mod api;
mod error;
mod server_options;

use api::api_twitter_users_me;
use server_options::ServerOptions;

const COOKIE: &str = "SESSION";

#[derive(Clone)]
struct AppState {
    oauth2_client: BasicClient,
    store: MemoryStore,
}

#[derive(Clone, Default)]
struct MemoryStore {
    store: Arc<RwLock<HashMap<String, Session>>>,
}

impl MemoryStore {
    async fn get(&self, key: &str) -> Option<Session> {
        self.store.read().await.get(key).cloned()
    }

    async fn put(&self, key: String, value: Session) {
        self.store.write().await.insert(key, value);
    }

    async fn del(&self, key: &str) {
        self.store.write().await.remove(key);
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let options = ServerOptions::parse();

    let oauth2_client = build_oauth2_client(options).expect("OAuth2 Client");
    let store = MemoryStore::default();
    let app_state = AppState {
        oauth2_client,
        store,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/user", get(user))
        .route("/auth/twitter", get(auth_twitter))
        .route("/auth/authorized", get(auth_authorized))
        .route("/api/twitter/users/me", get(api_twitter_users_me))
        .route("/logout", get(logout))
        .with_state(app_state);

    let config = RustlsConfig::from_pem_file("ssl/cert.pem", "ssl/key.pem")
        .await
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], 443));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn build_oauth2_client(
    ServerOptions {
        client_id,
        client_secret,
        redirect_url,
        auth_url,
        token_url,
    }: ServerOptions,
) -> Result<BasicClient, Box<dyn Error>> {
    Ok(BasicClient::new(
        ClientId::new(client_id),
        ClientSecret::new(client_secret).into(),
        AuthUrl::new(auth_url)?,
        TokenUrl::new(token_url)?.into(),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?))
}

async fn index() -> Html<String> {
    // async fn index() -> Html<&'static str> {
    Html(
        tokio::fs::read_to_string("html/index.html")
            .await
            .expect("index.html"),
    )
    // Html(include_str!("../html/index.html"))
}

async fn auth_twitter(State(oauth2_client): State<BasicClient>) -> impl IntoResponse {
    let (url, _csrf_token) = oauth2_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            [
                "like.read",
                "like.write",
                "tweet.read",
                "tweet.write",
                "users.read",
                "offline.access",
            ]
            .map(str::to_owned)
            .map(Scope::new),
        )
        .add_extra_param("code_challenge", "challenge")
        .add_extra_param("code_challenge_method", "plain")
        .url();

    Redirect::to(url.as_ref())
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AuthQuery {
    code: String,
    state: String,
}

async fn auth_authorized(
    Query(auth_query): Query<AuthQuery>,
    State(store): State<MemoryStore>,
    State(oauth2_client): State<BasicClient>,
) -> impl IntoResponse {
    let token = match oauth2_client
        .exchange_code(AuthorizationCode::new(auth_query.code))
        .add_extra_param("code_verifier", "challenge")
        .request_async(async_http_client)
        .await
    {
        Ok(token) => token,
        Err(err) => {
            log::error!("{err}: {:?}", err.source());
            panic!("auth authorized failed: {err}");
        }
    };

    let mut headers = HeaderMap::new();
    let mut auth_value =
        header::HeaderValue::from_str(&format!("Bearer {}", token.access_token().secret()))
            .expect("header value");
    auth_value.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, auth_value);

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client");

    let session = Session { client, token };

    let id = uuid::Uuid::new_v4().to_string();

    let cookie = format!("{COOKIE}={id}; SameSite=Lax; Path=/");

    store.put(id, session).await;

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().expect("valid cookie"));

    (headers, Redirect::to("/"))
}

async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> impl IntoResponse {
    let cookie = cookies.get(COOKIE).expect("session cookie");
    store.del(cookie).await;
    Redirect::to("/")
}

async fn user(session: Session) -> impl IntoResponse {
    Json(session)
}

#[derive(Clone, Serialize)]
pub struct Session {
    token: BasicTokenResponse,
    #[serde(skip)]
    client: reqwest::Client,
}

pub struct Unauthorized;

impl IntoResponse for Unauthorized {
    fn into_response(self) -> Response {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Session
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Unauthorized;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => Unauthorized,
                    _ => panic!("unexpected error getting Cookie header(s): {e}"),
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;

        let session_cookie = cookies.get(COOKIE).ok_or(Unauthorized)?;

        let store = MemoryStore::from_ref(state);

        store.get(session_cookie).await.ok_or(Unauthorized)
    }
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(input: &AppState) -> Self {
        input.oauth2_client.clone()
    }
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(input: &AppState) -> Self {
        input.store.clone()
    }
}
