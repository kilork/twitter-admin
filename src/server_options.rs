use clap::Parser;

#[derive(Debug, Parser)]
pub struct ServerOptions {
    /// Client ID from Twitter App.
    #[clap(env = "CLIENT_ID", long)]
    pub client_id: String,
    /// Client Secret from Twitter App.
    #[clap(env = "CLIENT_SECRET", long)]
    pub client_secret: String,
    #[clap(
        env = "REDIRECT_URL",
        default_value = "https://mysite.local/auth/authorized",
        long
    )]
    pub redirect_url: String,
    #[clap(
        env = "AUTH_URL",
        default_value = "https://twitter.com/i/oauth2/authorize",
        long
    )]
    pub auth_url: String,
    #[clap(
        env = "TOKEN_URL",
        default_value = "https://api.twitter.com/2/oauth2/token",
        long
    )]
    pub token_url: String,
}
