use super::*;
use http::*;
use http::jwt::data::{LoginData, OutputStatusData, TokenData, OutputData};
use http::jwt::{JwtCollection, Settings}; 
use actix_web::{test, App, http::StatusCode};
use std::sync::*;
use serde_json;

#[actix_rt::test]
async fn test_status() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));

	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(get_status)).await;
	let req = test::TestRequest::get().uri("/api/status").to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, true);
}

#[actix_rt::test]
async fn test_bad_login_rsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let login_data = TokenData{token: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/rsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_login_rsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/rsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_login_hmac() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/hmac").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_bad_login_hmac() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let login_data = TokenData{token: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/hmac").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_login_ecdsa() {	
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));

	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/ecdsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_bad_login_ecdsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let login_data = TokenData{token: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/ecdsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_verify_rsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/rsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try verify it
	let token_data = TokenData{token: resp_struct.access_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/rsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, true);	
}

#[actix_rt::test]
async fn test_bad_verify_rsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let token_data = TokenData{token: "1eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDUxNzg4NjQsImlhdCI6MTYwNTE3NTI2NCwiaXNzIjoic2ltcGxlX2p3dCIsInN1YiI6ImF1dGgiLCJuYW1lIjoidGVzdCB1c2VyIG5hbWUifQ.YsDyDOH6oITfS_F21gWsa7c91QY_yFDNbMlVVxyinXIu4jGSyKpLLjvMQohnEvuDlPSNGFKxZH9vprpkToVa7HzrBVp242NDIczyePw_UkaG11Hvm5JN03Twyy9fePoq9ft0FQvuCtgEN8YpZj_cOQFOmmVReRnkpU4XJQ58jF_HM0DWeAAIeAxQuWel7yhealbkmmdvZOiYe0pvYDX-TtRnFH3BvYeWB1-7Y_etaojBFUFMA5PnRDDzriN7CtYNCQd0xjdKwx8HYMTP0SFG64Dvh7Fz5Zrk6MvFiQUGA2ORXavetmeX1aExifOqOqaVPum3j71bcRNDeOOUZ89OkA".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/rsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, false);	
}

#[actix_rt::test]
async fn test_verify_hmac() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/hmac").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try verify it
	let token_data = TokenData{token: resp_struct.access_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/hmac").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, true);	
}

#[actix_rt::test]
async fn test_bad_verify_hmac() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let token_data = TokenData{token: "1.1.1".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/hmac").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, false);	
}

#[actix_rt::test]
async fn test_verify_ecdsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/ecdsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try verify it
	let token_data = TokenData{token: resp_struct.access_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/ecdsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, true);	
}

#[actix_rt::test]
async fn test_bad_verify_ecdsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	let token_data = TokenData{token: "1.1.1".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_verify)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/verify/ecdsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
 	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputStatusData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	assert_eq!(resp_struct.result, false);	
}

#[actix_rt::test]
async fn test_refresh_token_rsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/rsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try get new one
	let token_data = TokenData{token: resp_struct.refresh_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_refresh_token)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/refreshToken/rsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());	
}

#[actix_rt::test]
async fn test_refresh_token_hmac() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/hmac").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try get new one
	let token_data = TokenData{token: resp_struct.refresh_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_refresh_token)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/refreshToken/hmac").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());	
}

#[actix_rt::test]
async fn test_refresh_token_ecdsa() {
	let settings: Settings = Settings::new("settings.toml").expect("error reading settings");	
	let jwt_collection: JwtCollection = JwtCollection::new(settings).expect("error creating collection of jwt tokens");
	let data = Arc::new(RwLock::new(jwt_collection));
	
	//get tokens
	let login_data = LoginData{user_name: "test user name".to_string()};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_login)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/login/ecdsa").set_json(&login_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());
	
	let response_body = match resp.response().body().as_ref() { 
        Some(actix_web::body::Body::Bytes(bytes)) => bytes,
        _ => panic!("Response error"),
    };
	let resp_struct: OutputData = serde_json::from_slice(&response_body.to_vec()).expect("error deserializing body");
	
	//try get new one
	let token_data = TokenData{token: resp_struct.refresh_token};
	let mut app = test::init_service(App::new().data(Arc::clone(&data)).service(post_refresh_token)).await;
	let req = test::TestRequest::post().header("content-type", "application/json").uri("/api/auth/refreshToken/ecdsa").set_json(&token_data).to_request();
	let resp = test::call_service(&mut app, req).await;
	assert!(resp.status().is_success());	
}