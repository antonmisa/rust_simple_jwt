#[derive(Serialize, Deserialize)]
pub struct OutputStatusData {
	pub result: bool,
	pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginData {
	pub user_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenData {
	pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct OutputData {
	pub access_token: String,
	pub refresh_token: String,
}