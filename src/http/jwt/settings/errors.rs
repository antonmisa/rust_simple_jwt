use std::io;
use toml::de;
use std::fmt;
use std::string::FromUtf8Error;
use openssl::error::ErrorStack;
use serde_json;
use std::time::SystemTimeError;

use derive_more::{Error};

#[derive(Debug, Error)]
pub enum CliError {
	Io(io::Error),
	ParseToml(de::Error),
	ParseErrorStack(ErrorStack),
	ParseSerdeError(serde_json::Error),
	ParseTokenError,
	ParseSysTimeError(SystemTimeError),
	ParseDecodeError(data_encoding::DecodeError),
	ParseUtf8Error(FromUtf8Error),
}

impl From<io::Error> for CliError {
	fn from(err: io::Error) -> CliError {
		CliError::Io(err)
	}
}

impl From<de::Error> for CliError {
	fn from(err: de::Error) -> CliError {
		CliError::ParseToml(err)
	}
}

impl From<ErrorStack> for CliError {
	fn from(err: ErrorStack) -> CliError {
		CliError::ParseErrorStack(err)
	}
}

impl From<serde_json::Error> for CliError {
	fn from(err: serde_json::Error) -> CliError {
		CliError::ParseSerdeError(err)
	}
}

impl From<SystemTimeError> for CliError {
	fn from(err: SystemTimeError) -> CliError {
		CliError::ParseSysTimeError(err)
	}
}

impl From<data_encoding::DecodeError> for CliError {
	fn from(err: data_encoding::DecodeError) -> CliError {
		CliError::ParseDecodeError(err)
	}
}

impl From<FromUtf8Error> for CliError {
	fn from(err: FromUtf8Error) -> CliError {
		CliError::ParseUtf8Error(err)
	}
}

impl fmt::Display for CliError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			CliError::Io(ref err) => write!(f, "IO error: {}", err),
			CliError::ParseToml(ref err) => write!(f, "Toml parse error: {}", err),
			CliError::ParseErrorStack(ref err) => write!(f, "ErrorStack parse error: {}", err),
			CliError::ParseSerdeError(ref err) => write!(f, "Json parse error: {}", err),
			CliError::ParseSysTimeError(ref err) => write!(f, "SystemTime error: {}", err),
			CliError::ParseDecodeError(ref err) => write!(f, "Decode error: {}", err),
			CliError::ParseUtf8Error(ref err) => write!(f, "String convertion error: {}", err),
			CliError::ParseTokenError => write!(f, "Token parse error"),
		}
	}
}