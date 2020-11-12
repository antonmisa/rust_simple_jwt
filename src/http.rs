pub mod jwt;
mod errors;
use errors::CliHttpError;
use jwt::{JwtCollection, Settings, CommonHeaderFunc, TokenType, CliConst, decode_token, parse_struct};
use jwt::data::{OutputStatusData, LoginData, TokenData, OutputData};
use actix_web::{web, get, post, App, HttpServer, HttpResponse, Responder, Result};
use std::sync::*;

pub struct CliHttpServer {
}

impl CliHttpServer {
	pub async fn new(settings: Settings) -> std::io::Result<()> {
		let url = format!("{}:{}", settings.http.host, settings.http.port);
		
		let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
		let data = Arc::new(RwLock::new(jwt_collection));
		
		HttpServer::new(move || {			
			App::new()
				.data(Arc::clone(&data))
				.service(get_status)
				.service(post_login)
				.service(post_refresh_token)
				.service(post_verify)
				.default_service(
					web::route().to(|| HttpResponse::NotFound())
                )
		})
        .bind(url)?
        .run()
		.await
	}
}

#[get("/api/status")]
pub async fn get_status<'a>(_data: web::Data<Arc<RwLock<JwtCollection>>>) -> impl Responder {
	web::Json( OutputStatusData {result: true, message: CliConst::OK.to_string()} )
}

#[post("/api/auth/login/{name}")]
pub async fn post_login<'a>(data: web::Data<Arc<RwLock<JwtCollection>>>, payload: web::Json<LoginData>, name: web::Path<String>) -> Result<web::Json<OutputData>, CliHttpError> {	
	match name.to_lowercase().as_ref() {
		"rsa" => {
			match data.try_read() {
				Ok(collection) => {
					let login_data = payload.into_inner();
					
					let claim_at = collection.jwt_rsa.get_claim(TokenType::AccessToken, &login_data)?;
					let data_at = collection.jwt_rsa.get_data(&claim_at);
					let at = collection.jwt_rsa.get_signature(&data_at)?;
					
					let claim_rt = collection.jwt_rsa.get_claim(TokenType::RefreshToken, &login_data)?;
					let data_rt = collection.jwt_rsa.get_data(&claim_rt);
					let rt = collection.jwt_rsa.get_signature(&data_rt)?;
					
					Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		"hmac" => {
			match data.try_read() {
				Ok(collection) => {
					let login_data = payload.into_inner();
					
					let claim_at = collection.jwt_hmac.get_claim(TokenType::AccessToken, &login_data)?;
					let data_at = collection.jwt_hmac.get_data(&claim_at);
					let at = collection.jwt_hmac.get_signature(&data_at)?;
					
					let claim_rt = collection.jwt_hmac.get_claim(TokenType::RefreshToken, &login_data)?;
					let data_rt = collection.jwt_hmac.get_data(&claim_rt);
					let rt = collection.jwt_hmac.get_signature(&data_rt)?;
					
					Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )
				},
				Err(_) => Err(CliHttpError::Timeout)
			}			
		},
		"ecdsa" => {
			match data.try_read() {
				Ok(collection) => {
					let login_data = payload.into_inner();
					
					let claim_at = collection.jwt_ecdsa.get_claim(TokenType::AccessToken, &login_data)?;
					let data_at = collection.jwt_ecdsa.get_data(&claim_at);
					let at = collection.jwt_ecdsa.get_signature(&data_at)?;
					
					let claim_rt = collection.jwt_ecdsa.get_claim(TokenType::RefreshToken, &login_data)?;
					let data_rt = collection.jwt_ecdsa.get_data(&claim_rt);
					let rt = collection.jwt_ecdsa.get_signature(&data_rt)?;
					
					Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		_ => Err(CliHttpError::BadClientData),
	}
}

#[post("/api/auth/verify/{name}")]
async fn post_verify(data: web::Data<Arc<RwLock<JwtCollection>>>, payload: web::Json<TokenData>, name: web::Path<String>) -> Result<web::Json<OutputStatusData>, CliHttpError> {
 	match name.to_lowercase().as_ref() {
		"rsa" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_rsa.get_verify(&payload.token)?;
					
					match result {
						true => Ok( web::Json( OutputStatusData { result: true, message: CliConst::TOKEN_VALID.to_string() } ) ),
						false => Ok( web::Json( OutputStatusData { result: false, message: CliConst::TOKEN_INVALID.to_string() } ) ),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		"hmac" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_hmac.get_verify(&payload.token)?;
					
					match result {
						true => Ok( web::Json( OutputStatusData { result: true, message: CliConst::TOKEN_VALID.to_string() } ) ),
						false => Ok( web::Json( OutputStatusData { result: false, message: CliConst::TOKEN_INVALID.to_string() } ) ),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}			
		},
		"ecdsa" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_ecdsa.get_verify(&payload.token)?;
					
					match result {
						true => Ok( web::Json( OutputStatusData { result: true, message: CliConst::TOKEN_VALID.to_string() } ) ),
						false => Ok( web::Json( OutputStatusData { result: false, message: CliConst::TOKEN_INVALID.to_string() } ) ),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		_ => Err(CliHttpError::BadClientData),
	}
}

#[post("/api/auth/refreshToken/{name}")]
async fn post_refresh_token(data: web::Data<Arc<RwLock<JwtCollection>>>, payload: web::Json<TokenData>, name: web::Path<String>) -> Result<web::Json<OutputData>, CliHttpError> {
 	match name.to_lowercase().as_ref() {
		"rsa" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_rsa.get_verify(&payload.token)?;
									
					match result {
						true =>  {
							let mut header = vec![0, 0];
							let mut claim = vec![0, 0];
							let (len_header, len_claim) = decode_token(&payload.token, &mut header, &mut claim)?;
							let (_, claim) = parse_struct(&header[..len_header], &claim[..len_claim])?;
							
							let login_data = LoginData{ user_name: claim.name.to_string()};
							
							let claim_at = collection.jwt_rsa.get_claim(TokenType::AccessToken, &login_data)?;
							let data_at = collection.jwt_rsa.get_data(&claim_at);
							let at = collection.jwt_rsa.get_signature(&data_at)?;
							
							let claim_rt = collection.jwt_rsa.get_claim(TokenType::RefreshToken, &login_data)?;
							let data_rt = collection.jwt_rsa.get_data(&claim_rt);
							let rt = collection.jwt_rsa.get_signature(&data_rt)?;
					
							Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )
						},
						false => Err(CliHttpError::BadClientData),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		"hmac" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_hmac.get_verify(&payload.token)?;
					
					match result {
						true => {
							let mut header = vec![0, 0];
							let mut claim = vec![0, 0];
							let (len_header, len_claim) = decode_token(&payload.token, &mut header, &mut claim)?;
							let (_, claim) = parse_struct(&header[..len_header], &claim[..len_claim])?;
							
							let login_data = LoginData{ user_name: claim.name.to_string()};
							
							let claim_at = collection.jwt_hmac.get_claim(TokenType::AccessToken, &login_data)?;
							let data_at = collection.jwt_hmac.get_data(&claim_at);
							let at = collection.jwt_hmac.get_signature(&data_at)?;
							
							let claim_rt = collection.jwt_hmac.get_claim(TokenType::RefreshToken, &login_data)?;
							let data_rt = collection.jwt_hmac.get_data(&claim_rt);
							let rt = collection.jwt_hmac.get_signature(&data_rt)?;
					
							Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )							
						},
						false => Err(CliHttpError::BadClientData),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}			
		},
		"ecdsa" => {
			match data.try_read() {
				Ok(collection) => {
					let result = collection.jwt_ecdsa.get_verify(&payload.token)?;
					
					match result {
						true => {
							let mut header = vec![0, 0];
							let mut claim = vec![0, 0];
							let (len_header, len_claim) = decode_token(&payload.token, &mut header, &mut claim)?;
							let (_, claim) = parse_struct(&header[..len_header], &claim[..len_claim])?;
							
							let login_data = LoginData{ user_name: claim.name.to_string()};
							
							let claim_at = collection.jwt_ecdsa.get_claim(TokenType::AccessToken, &login_data)?;
							let data_at = collection.jwt_ecdsa.get_data(&claim_at);
							let at = collection.jwt_ecdsa.get_signature(&data_at)?;
							
							let claim_rt = collection.jwt_ecdsa.get_claim(TokenType::RefreshToken, &login_data)?;
							let data_rt = collection.jwt_ecdsa.get_data(&claim_rt);
							let rt = collection.jwt_ecdsa.get_signature(&data_rt)?;
					
							Ok( web::Json( OutputData { access_token: format!("{}.{}", data_at, at), refresh_token: format!("{}.{}", data_rt, rt) } ) )							
						},
						false => Err(CliHttpError::BadClientData),
					}
				},
				Err(_) => Err(CliHttpError::Timeout)
			}
		},
		_ => Err(CliHttpError::BadClientData),
	}    
}
