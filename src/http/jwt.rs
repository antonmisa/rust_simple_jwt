use std::sync::*;
use openssl::rsa::{Padding};
use openssl::error::ErrorStack;
use openssl::pkey::{Public, Private};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;

use std::time::{UNIX_EPOCH, Duration, SystemTime};
use data_encoding::{BASE64URL_NOPAD};
use serde_json;

pub mod settings;
pub use settings::{Settings, HSAlgorithmType, RSAlgorithmType};
pub use settings::errors::CliError;

pub mod data;
pub use data::{LoginData, TokenData};

pub mod consts;
pub use consts::CliConst;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<'a, 'b> {
    pub exp: u64,             // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: u64,             // Optional. Issued at (as UTC timestamp)
    pub iss: &'a str,         // Optional. Issuer
    pub sub: &'a str,         // Optional. Subject (whom token refers to)
	pub name: &'b str,        // Optional. User name
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header<'a, 'b> {
    pub alg: &'a str,         // Required. Algorithm of signature
    pub typ: &'b str,         // Required. Signature type
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenType {
	AccessToken,
	RefreshToken,
}

trait CommonCryptFunc {
	fn sign(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack>;
	fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ErrorStack>;	
}

pub trait CommonHeaderFunc { 
	fn get_claim(&self, token_type: TokenType, data: &LoginData) -> Result<String, settings::errors::CliError>;
	fn get_data(&self, claim: &str) -> String;
	fn get_signature(&self, data: &str) -> Result<String, settings::errors::CliError>;
	fn get_verify(&self, data: &str) -> Result<bool, settings::errors::CliError>;
}

#[derive(Clone)]
pub struct JwtCollection {
	pub jwt_rsa: JwtRs,
	pub jwt_hmac: JwtHs,
	pub jwt_ecdsa: JwtEs,
	settings: Arc<Settings>,
}

impl JwtCollection {
	pub fn new(settings: Settings) -> Result<JwtCollection, settings::errors::CliError> {	
		let s = Arc::new(settings);
	
		let a = JwtRs::new(Arc::clone(&s))?;
		let b = JwtHs::new(Arc::clone(&s))?;
		let c = JwtEs::new(Arc::clone(&s))?;
		
		Ok(JwtCollection{ jwt_rsa: a, jwt_hmac: b, jwt_ecdsa: c, settings: Arc::clone(&s) })
	}
}

pub fn decode_token(from: &str, mut header: &mut Vec<u8>, mut claim: &mut Vec<u8>) -> Result<(usize, usize), settings::errors::CliError> {
	let parts: Vec<&str> = from.split(".").collect();
	
	let len = BASE64URL_NOPAD.decode_len(parts[1].len())?;
	claim.resize(len, 0);
	let len_claim = BASE64URL_NOPAD.decode_mut(parts[1].as_bytes(), &mut claim).map_err(|e| e.error)?;
	
	let len = BASE64URL_NOPAD.decode_len(parts[0].len())?;
	header.resize(len, 0);
	let len_header = BASE64URL_NOPAD.decode_mut(parts[0].as_bytes(), &mut header).map_err(|e| e.error)?;

	Ok((len_header, len_claim))
}

pub fn parse_struct<'a>(header: &'a [u8], claim: &'a [u8]) -> Result<(Header<'a, 'a>, Claims<'a, 'a>), settings::errors::CliError> {
	let h = serde_json::from_slice(header)?;
	let c = serde_json::from_slice(claim)?;
	
	Ok((h, c))
}

fn parse_token(data: &str) -> Result<Vec<&str>, settings::errors::CliError> {
	let parts: Vec<&str> = data.split(".").collect();
	
	match parts.len() {
		3 => Ok(parts),
		_ => Err(settings::errors::CliError::ParseTokenError),
	}
}

#[derive(Clone)]
pub struct JwtRs {
	public_key: PKey<Public>,
	private_key: PKey<Private>,	
	
	settings: Arc<Settings>,
	header64: String,
}

impl JwtRs {
	pub fn new(settings: Arc<Settings>) -> Result<JwtRs, settings::errors::CliError> {
		let rsa_public_key = PKey::public_key_from_pem(settings.keys.rsa_public_key.as_bytes())?;
		let rsa_private_key = PKey::private_key_from_pem(settings.keys.rsa_private_key.as_bytes())?;
		
		let header = Header { alg: &settings.algorithm.rs_algorithm.to_string(), typ: "JWT" };
		let header_string = serde_json::to_string(&header)?;
		let header64 = BASE64URL_NOPAD.encode(header_string.as_bytes());	
		
		Ok(JwtRs { public_key: rsa_public_key, private_key: rsa_private_key, header64: header64, settings: settings } )
	}	
}

impl CommonHeaderFunc for JwtRs {
	fn get_claim(&self, token_type: TokenType, data: &LoginData) -> Result<String, settings::errors::CliError> {
		let exp: u64 = match token_type {
							TokenType::AccessToken => self.settings.expire.access_token_expire,
							TokenType::RefreshToken => self.settings.expire.refresh_token_expire,
						};
		let start = SystemTime::now();
		let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
		let next = start.checked_add(Duration::from_secs(exp)).expect(CliConst::MATH_OVERFLOW);
		let end = next.duration_since(UNIX_EPOCH)?;
		
		let claim = Claims { exp: end.as_secs(), iat: since_the_epoch.as_secs(), iss: &self.settings.common.iss, sub: &self.settings.common.sub, name: &data.user_name };
		let claim_string = serde_json::to_string(&claim)?;
		let claim64 = BASE64URL_NOPAD.encode(claim_string.as_bytes()); 
		
		Ok(claim64)
		
	}
	
	fn get_data(&self, claim: &str) -> String {
		let data = format!("{}.{}", self.header64, claim);

		data
	}
	
	fn get_signature(&self, data: &str) -> Result<String, settings::errors::CliError> {
		let mut buf: Vec<u8> = vec![0; self.private_key.size() as usize];	
		let ln = self.sign(data.as_bytes(), &mut buf)?;		
		let signature = BASE64URL_NOPAD.encode(&buf[..ln]);
		
		Ok(signature)
	}		
	
	fn get_verify(&self, data: &str) -> Result<bool, settings::errors::CliError> {
		match parse_token(data) {
			Ok(parts) => {
				match BASE64URL_NOPAD.decode(parts[2].as_bytes()) {
					Ok(signature) => {
						let d = format!("{}.{}", parts[0], parts[1]);

						match self.public_key.size() as usize >= signature.len() {
							true => {
								match self.verify(&d.as_bytes(), &signature) {
									Ok(result) => {
										match result {
											true => {
												let start = SystemTime::now();
												let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
										
												match BASE64URL_NOPAD.decode(parts[1].as_bytes()) {
													Ok(claim_bytes) => {				
														let claim: Claims = serde_json::from_slice(&claim_bytes)?;
												
														Ok(claim.exp >= since_the_epoch.as_secs())
													},
													Err(_) => Ok(false),
												}
											},
											false => Ok(false),
										}
									},
									Err(_) => Ok(false),
								}
							}
							false => Ok(false),
						}							
					},
					Err(_) => Ok(false),
				}				
			},
			Err(_) => Ok(false),
		}
	}
}

impl CommonCryptFunc for JwtRs {
	fn sign(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
		let mut signer = match self.settings.algorithm.rs_algorithm {
			RSAlgorithmType::RS256 => Signer::new(MessageDigest::sha256(), &self.private_key)?,
			RSAlgorithmType::RS512 => Signer::new(MessageDigest::sha512(), &self.private_key)?,
		};
		signer.set_rsa_padding(Padding::PKCS1)?;
		
		signer.sign_oneshot(to, from)
	}
	
	fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {	
		let mut verifier = match self.settings.algorithm.rs_algorithm {
			RSAlgorithmType::RS256 => Verifier::new(MessageDigest::sha256(), &self.public_key)?,
			RSAlgorithmType::RS512 => Verifier::new(MessageDigest::sha512(), &self.public_key)?,
		};
		verifier.set_rsa_padding(Padding::PKCS1)?;	
		
		verifier.verify_oneshot(signature, data)
	}
}

#[derive(Clone)]
pub struct JwtHs {
	key: PKey<Private>,
	
	settings: Arc<Settings>,
	header64: String,	
}

impl JwtHs {
	pub fn new(settings: Arc<Settings>) -> Result<JwtHs, settings::errors::CliError> {
		let key = PKey::hmac(settings.keys.hmac_key.as_bytes())?;
		
		let header = Header { alg: &settings.algorithm.hs_algorithm.to_string(), typ: "JWT" };
		let header_string = serde_json::to_string(&header)?;
		let header64 = BASE64URL_NOPAD.encode(header_string.as_bytes());
		
		Ok(JwtHs { key: key, header64: header64, settings: settings })
	}	
}

impl CommonCryptFunc for JwtHs {
	fn sign(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
		let mut signer = match self.settings.algorithm.hs_algorithm {
			HSAlgorithmType::HS256 => Signer::new(MessageDigest::sha256(), &self.key)?,
			HSAlgorithmType::HS512 => Signer::new(MessageDigest::sha512(), &self.key)?,
		};

		signer.sign_oneshot(to, from)	
	}
	
	fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
		let mut buf: Vec<u8> = vec![0; self.key.size() as usize];
		let ln = self.sign(data, &mut buf)?;
		
		Ok(openssl::memcmp::eq(&buf[..ln], &signature))
	}	
}

impl CommonHeaderFunc for JwtHs {	
	fn get_claim(&self, token_type: TokenType, data: &LoginData) -> Result<String, settings::errors::CliError> {
		let exp: u64 = match token_type {
							TokenType::AccessToken => self.settings.expire.access_token_expire,
							TokenType::RefreshToken => self.settings.expire.refresh_token_expire,
						};
		let start = SystemTime::now();
		let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
		let next = start.checked_add(Duration::from_secs(exp)).expect(CliConst::MATH_OVERFLOW);
		let end = next.duration_since(UNIX_EPOCH)?;
		
		let claim = Claims { exp: end.as_secs(), iat: since_the_epoch.as_secs(), iss: &self.settings.common.iss, sub: &self.settings.common.sub, name: &data.user_name };
		let claim_string = serde_json::to_string(&claim)?;
		let claim64 = BASE64URL_NOPAD.encode(claim_string.as_bytes()); 
		
		Ok(claim64)
	}
	
	fn get_data(&self, claim: &str) -> String {
		let data = format!("{}.{}", self.header64, claim);

		data
	}
	
	fn get_signature(&self, data: &str) -> Result<String, settings::errors::CliError> {
		let mut buf: Vec<u8> = vec![0; self.key.size() as usize];
		let ln = self.sign(data.as_bytes(), &mut buf)?;
		
		let signature = BASE64URL_NOPAD.encode(&buf[..ln]);
		
		Ok(signature)
	}		

	fn get_verify(&self, data: &str) -> Result<bool, settings::errors::CliError> {
		match parse_token(data) {
			Ok(parts) => {
				match BASE64URL_NOPAD.decode(parts[2].as_bytes()) {
					Ok(signature) => {
						let d = format!("{}.{}", parts[0], parts[1]);

						match self.key.size() as usize >= signature.len() {
							true => {
								match self.verify(&d.as_bytes(), &signature) {
									Ok(result) => {
										match result {
											true => {
												let start = SystemTime::now();
												let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
										
												match BASE64URL_NOPAD.decode(parts[1].as_bytes()) {
													Ok(claim_bytes) => {				
														let claim: Claims = serde_json::from_slice(&claim_bytes)?;
												
														Ok(claim.exp >= since_the_epoch.as_secs())
													},
													Err(_) => Ok(false),
												}
											},
											false => Ok(false),
										}
									},
									Err(_) => Ok(false),
								}
							},
							false => Ok(false),
						}
					},
					Err(_) => Ok(false),
				}				
			},
			Err(_) => Ok(false),
		}
	}	
}

#[derive(Clone)]
pub struct JwtEs {
	ec_public_key: EcKey<Public>,
	ec_private_key: EcKey<Private>,
	
	pk_public_pkey: PKey<Public>,
	pk_private_pkey: PKey<Private>,	
	
	settings: Arc<Settings>,
	header64: String,
}

impl JwtEs {
	pub fn new(settings: Arc<Settings>) -> Result<JwtEs, settings::errors::CliError> {		
		let ec_public_key = EcKey::public_key_from_pem(settings.keys.ec_public_key.as_bytes())?;
		let ec_private_key = EcKey::private_key_from_pem(settings.keys.ec_private_key.as_bytes())?;
		
		let pk_public_pkey = PKey::from_ec_key(ec_public_key.clone())?;
		let pk_private_pkey = PKey::from_ec_key(ec_private_key.clone())?;
		
		let header = Header { alg: &settings.algorithm.ec_algorithm.to_string(), typ: "JWT" };
		let header_string = serde_json::to_string(&header)?;
		let header64 = BASE64URL_NOPAD.encode(header_string.as_bytes());
		
		Ok(JwtEs { ec_public_key: ec_public_key, ec_private_key: ec_private_key, pk_public_pkey: pk_public_pkey, pk_private_pkey: pk_private_pkey, header64: header64, settings: settings } )	
	}	
}

impl CommonCryptFunc for JwtEs {
	fn sign(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
 		let sig = EcdsaSig::sign(from, &self.ec_private_key)?;
		let v = sig.to_der()?;
		let ln = v.len();
		
		to[..ln].copy_from_slice(&v[..ln]);
		
		Ok(ln)		
	}
	
	fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
		let sig = EcdsaSig::from_der(signature)?;
 		let result = sig.verify(data, &self.ec_public_key)?;
		
		Ok(result)
	}	
}

impl CommonHeaderFunc for JwtEs {	
	fn get_claim(&self, token_type: TokenType, data: &LoginData) -> Result<String, settings::errors::CliError> {
		let exp: u64 = match token_type {
							TokenType::AccessToken => self.settings.expire.access_token_expire,
							TokenType::RefreshToken => self.settings.expire.refresh_token_expire,
						};
		let start = SystemTime::now();
		let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
		let next = start.checked_add(Duration::from_secs(exp)).expect(CliConst::MATH_OVERFLOW);
		let end = next.duration_since(UNIX_EPOCH)?;
		
		let claim = Claims { exp: end.as_secs(), iat: since_the_epoch.as_secs(), iss: &self.settings.common.iss, sub: &self.settings.common.sub, name: &data.user_name };
		let claim_string = serde_json::to_string(&claim)?;
		let claim64 = BASE64URL_NOPAD.encode(claim_string.as_bytes()); 
		
		Ok(claim64)
	}
	
	fn get_data(&self, claim: &str) -> String {
		let data = format!("{}.{}", self.header64, claim);

		data
	}
	
	fn get_signature(&self, data: &str) -> Result<String, settings::errors::CliError> {
		let mut buf = vec![0; self.pk_private_pkey.size() as usize];	
		let ln = self.sign(data.as_bytes(), &mut buf)?;
		let signature = BASE64URL_NOPAD.encode(&buf[..ln]);
		
		Ok(signature)
	}		
	
	fn get_verify(&self, data: &str) -> Result<bool, settings::errors::CliError> {
		match parse_token(data) {
			Ok(parts) => {
				match BASE64URL_NOPAD.decode(parts[2].as_bytes()) {
					Ok(signature) => {
						let d = format!("{}.{}", parts[0], parts[1]);
						
						match self.pk_public_pkey.size() as usize >= signature.len() {
							true => {
								match self.verify(&d.as_bytes(), &signature) {
									Ok(result) => {
										match result {
											true => {
												let start = SystemTime::now();
												let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
										
												match BASE64URL_NOPAD.decode(parts[1].as_bytes()) {
													Ok(claim_bytes) => {				
														let claim: Claims = serde_json::from_slice(&claim_bytes)?;
												
														Ok(claim.exp >= since_the_epoch.as_secs())
													},
													Err(_) => Ok(false),
												}
											},
											false => Ok(false),
										}
									},
									Err(_) => Ok(false),
								}
							},
							false => Ok(false),
						}
					},
					Err(_) => Ok(false),
				}				
			},
			Err(_) => Ok(false),
		}
	}	
}