use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{error::AppError, Session};

#[derive(Deserialize)]
pub struct UserResponse {
    data: User,
}

#[derive(Deserialize, Serialize)]
pub struct User {
    id: String,
    name: String,
    username: String,
}

pub async fn api_twitter_users_me(session: Session) -> Result<Json<User>, AppError> {
    session
        .client
        .get("https://api.twitter.com/2/users/me")
        .send()
        .await
        .map_err(|err| AppError::InternalError(err.to_string()))?
        .json::<UserResponse>()
        .await
        .map(|response| Json(response.data))
        .map_err(|err| AppError::InternalError(err.to_string()))
}
