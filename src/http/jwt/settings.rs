use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::io::Read;
pub mod errors;

use errors::CliError;
use toml;

#[derive(Deserialize, Debug)]
pub struct Settings {
	path: PathSettings,
	pub algorithm: AlgorithmSettings,
	pub common: CommonSettings,
	pub expire: ExpireSettings,
	pub http: HttpSettings,
	#[serde(skip_deserializing,skip_serializing)]
	pub keys: KeysSettings
}

impl Settings {	
	pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Settings, CliError> {
		let mut file = File::open(file_path)?;
		let mut contents = String::new();
		file.read_to_string(&mut contents)?;
		let mut data: Settings = toml::from_str(&contents)?;
		
		//reading rsa keys
		let rsa_public_key_content = read_file(&data.path.rsa_public_key)?;
		let rsa_private_key_content = read_file(&data.path.rsa_private_key)?;
		
		//reading ecdsa keys
		let ec_public_key_content = read_file(&data.path.ec_public_key)?;
		let ec_private_key_content = read_file(&data.path.ec_private_key)?;		
		
		data.keys = KeysSettings { 
			rsa_public_key: rsa_public_key_content, 
			rsa_private_key: rsa_private_key_content, 
			hmac_key: data.path.hmac_key.to_string(),
			ec_public_key: ec_public_key_content, 
			ec_private_key: ec_private_key_content,
		};
		Ok(data)
	}
}

fn read_file<P: AsRef<Path>>(file_path: P) -> Result<String, CliError> {
	let mut file = File::open(file_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	Ok(contents)
}

#[derive(Deserialize, Debug)]
struct PathSettings {
	#[serde(alias = "rsa_public_key")]
	rsa_public_key: String,
	#[serde(alias = "rsa_private_key")]
	rsa_private_key: String,
	#[serde(alias = "hmac_key")]
	hmac_key: String,
	#[serde(alias = "ec_public_key")]
	ec_public_key: String,
	#[serde(alias = "ec_private_key")]
	ec_private_key: String,	
}

#[derive(Deserialize, Debug)]
pub enum RSAlgorithmType { RS256, RS512 }

impl fmt::Display for RSAlgorithmType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			RSAlgorithmType::RS256 => write!(f, "RS256"),
			RSAlgorithmType::RS512 => write!(f, "RS512"),
		}
	}
}

#[derive(Deserialize, Debug)]
pub enum HSAlgorithmType { HS256, HS512 }

impl fmt::Display for HSAlgorithmType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			HSAlgorithmType::HS256 => write!(f, "HS256"),
			HSAlgorithmType::HS512 => write!(f, "HS512"),
		}
	}
}

#[derive(Deserialize, Debug)]
pub enum ESAlgorithmType { ES256, ES512 }

impl fmt::Display for ESAlgorithmType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			ESAlgorithmType::ES256 => write!(f, "ES256"),
			ESAlgorithmType::ES512 => write!(f, "ES512"),
		}
	}
}

#[derive(Deserialize, Debug)]
pub struct AlgorithmSettings {
	#[serde(alias = "algRS")]
	pub rs_algorithm: RSAlgorithmType,
	#[serde(alias = "algHS")]
	pub hs_algorithm: HSAlgorithmType,
	#[serde(alias = "algES")]
	pub ec_algorithm: ESAlgorithmType,
}

#[derive(Deserialize, Debug)]
pub struct CommonSettings {
	pub iss: String,
	pub sub: String,
}

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct ExpireSettings {
	#[serde(alias = "expAT")]
	pub access_token_expire: u64,
	#[serde(alias = "expRT")]
	pub refresh_token_expire: u64,
}

#[derive(Deserialize, Debug)]
pub struct HttpSettings {
	pub host: String,
	pub port: u32,
}

#[derive(Debug, Default)]
pub struct KeysSettings {	
	pub rsa_public_key: String,
	pub rsa_private_key: String,
	pub hmac_key: String,
	pub ec_public_key: String,
	pub ec_private_key: String,	
}