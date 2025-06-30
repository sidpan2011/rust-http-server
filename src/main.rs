use actix_web::{web, App, HttpServer, HttpResponse, Result, error::ResponseError};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer, Signature};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use spl_token::instruction as token_instruction;
use std::collections::HashMap;
use std::fmt;
use bs58;

// Custom error type
#[derive(Debug)]
enum ServerError {
    KeypairGenerationFailed,
    InvalidRequest,
    InternalError,
    InvalidPubkey,
    InvalidSecretKey,
    MissingFields,
    InvalidSignature,
    InvalidLamports,
    SameAddresses,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerError::KeypairGenerationFailed => write!(f, "Failed to generate keypair"),
            ServerError::InvalidRequest => write!(f, "Invalid request"),
            ServerError::InternalError => write!(f, "Internal server error"),
            ServerError::InvalidPubkey => write!(f, "Invalid public key"),
            ServerError::InvalidSecretKey => write!(f, "Invalid secret key"),
            ServerError::MissingFields => write!(f, "Missing required fields"),
            ServerError::InvalidSignature => write!(f, "Invalid signature"),
            ServerError::InvalidLamports => write!(f, "Invalid lamports amount"),
            ServerError::SameAddresses => write!(f, "Sender and recipient cannot be the same"),
        }
    }
}

impl ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        let error_message = self.to_string();
        let api_response = ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(error_message),
        };
        
        HttpResponse::BadRequest().json(api_response)
    }
}

// Response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

// Generate a new Solana keypair with error handling
async fn generate_keypair() -> Result<HttpResponse, ServerError> {
    // Create a new random keypair
    let keypair = match std::panic::catch_unwind(|| Keypair::new()) {
        Ok(kp) => kp,
        Err(_) => return Err(ServerError::KeypairGenerationFailed),
    };
    
    // Get the public key as base58 string
    let pubkey = keypair.pubkey().to_string();
    
    // Get the secret key as base58 string
    let secret = match std::panic::catch_unwind(|| bs58::encode(keypair.to_bytes()).into_string()) {
        Ok(sec) => sec,
        Err(_) => return Err(ServerError::KeypairGenerationFailed),
    };
    
    let response_data = KeypairResponse {
        pubkey,
        secret,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse, ServerError> {
    let mint_authority = match req.mint_authority.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let decimals = req.decimals;
    
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return Err(ServerError::InternalError),
    };
    
    let mut accounts = Vec::new();
    for account_meta in &instruction.accounts {
        let account_response = AccountMetaResponse {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        };
        accounts.push(account_response);
    }
    
    let instruction_data = base64::encode(&instruction.data);
    
    let response_data = CreateTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse, ServerError> {
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let destination = match req.destination.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let authority = match req.authority.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let amount = req.amount;
    
    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Err(ServerError::InternalError),
    };
    
    let mut accounts = Vec::new();
    for account_meta in &instruction.accounts {
        let account_response = AccountMetaResponse {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        };
        accounts.push(account_response);
    }
    
    let instruction_data = base64::encode(&instruction.data);
    
    let response_data = MintTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse, ServerError> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Err(ServerError::MissingFields);
    }
    
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Err(ServerError::InvalidSecretKey),
    };
    
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Err(ServerError::InvalidSecretKey),
    };
    
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let signature_base64 = base64::encode(signature.as_ref());
    
    let response_data = SignMessageResponse {
        signature: signature_base64,
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse, ServerError> {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Err(ServerError::MissingFields);
    }
    
    let pubkey = match req.pubkey.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Err(ServerError::InvalidSignature),
    };
    
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Err(ServerError::InvalidSignature),
    };
    
    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);
    
    let response_data = VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse, ServerError> {
    if req.from.is_empty() || req.to.is_empty() {
        return Err(ServerError::MissingFields);
    }
    
    if req.lamports == 0 {
        return Err(ServerError::InvalidLamports);
    }
    
    if req.lamports > 1_000_000_000_000_000_000 {
        return Err(ServerError::InvalidLamports);
    }
    
    let from_pubkey = match req.from.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    let to_pubkey = match req.to.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    
    if from_pubkey == to_pubkey {
        return Err(ServerError::SameAddresses);
    }
    
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);
    
    let mut accounts = Vec::new();
    for account_meta in &instruction.accounts {
        accounts.push(account_meta.pubkey.to_string());
    }
    
    let instruction_data = base64::encode(&instruction.data);
    
    let response_data = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse, ServerError> {
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return Err(ServerError::MissingFields);
    }
    if req.amount == 0 {
        return Err(ServerError::InvalidLamports);
    }
    let destination = match req.destination.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    let owner = match req.owner.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return Err(ServerError::InvalidPubkey),
    };
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &mint,
        &destination,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Err(ServerError::InternalError),
    };
    let mut accounts = Vec::new();
    for account_meta in &instruction.accounts {
        let account_response = AccountMetaResponse {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        };
        accounts.push(account_response);
    }
    let instruction_data = base64::encode(&instruction.data);
    let response_data = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    Ok(HttpResponse::Ok().json(api_response))
}

// Health check endpoint
async fn health_check() -> Result<HttpResponse, ServerError> {
    let mut status_map = HashMap::new();
    status_map.insert("status".to_string(), "ok".to_string());
    
    let api_response = ApiResponse {
        success: true,
        data: Some(status_map),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

// Error handler for 404
async fn not_found() -> Result<HttpResponse, ServerError> {
    let api_response = ApiResponse::<()> {
        success: false,
        data: None,
        error: Some("Endpoint not found".to_string()),
    };
    
    Ok(HttpResponse::BadRequest().json(api_response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Solana HTTP Server...");
    println!("Server will be available at: http://127.0.0.1:8080");
    println!("Keypair endpoint: POST /keypair");
    println!("Create token endpoint: POST /token/create");
    println!("Mint token endpoint: POST /token/mint");
    println!("Sign message endpoint: POST /message/sign");
    println!("Verify message endpoint: POST /message/verify");
    println!("Send SOL endpoint: POST /send/sol");
    println!("Send token endpoint: POST /send/token");
    println!("Health check: GET /health");
    
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
            .route("/health", web::get().to(health_check))
            .default_service(web::route().to(not_found))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
