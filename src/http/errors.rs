use actix_web::{
    dev::HttpResponseBuilder, error, http::header, http::StatusCode, HttpResponse,
};
use derive_more::{Display, Error};

use crate::http::jwt::CliError;

#[derive(Debug, Display, Error)]
pub enum CliHttpError {
    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "timeout")]
    Timeout,
	
	#[display(fmt = "internal error")]
	ParseCliError(CliError),
}

impl From<CliError> for CliHttpError {
	fn from(err: CliError) -> CliHttpError {
		CliHttpError::ParseCliError(err)
	}
}

impl error::ResponseError for CliHttpError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "application/json")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            CliHttpError::BadClientData => StatusCode::BAD_REQUEST,
            CliHttpError::Timeout => StatusCode::GATEWAY_TIMEOUT,
			CliHttpError::ParseCliError(ref _err) => {
				println!("{:?}", _err);
				StatusCode::INTERNAL_SERVER_ERROR
			},
        }
    }
}