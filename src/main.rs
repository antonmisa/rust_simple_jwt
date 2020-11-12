#[macro_use] extern crate serde_derive;

mod http;
use http::jwt::{Settings};
use http::CliHttpServer;

#[cfg(test)]
mod test;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let local_settings: Settings = Settings::new("settings.toml").expect("error reading settings");
	CliHttpServer::new(local_settings).await
}