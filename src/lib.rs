use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rmp_serde::{from_slice, to_vec};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use std::error::Error;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// Custom error type for token-related errors.
#[derive(Debug)]
pub struct TokenError(String);

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for TokenError {}

// A trait to define the expiration time for tokens.
pub trait Expirable {
    // Returns the expiration timestamp (Unix timestamp).
    fn exp(&self) -> i64;
}

// Creates a token from the provided payload and secret.
// 
// This function serializes the payload, signs it with the secret, 
// and returns a JWT-like string consisting of a base64url-encoded payload 
// and a base64url-encoded signature. The token is used for authentication 
// and authorization purposes.
//
// # Arguments
//
// * `payload` - The data to be serialized into the token.
// * `secret` - The secret key used to sign the token.
//
// # Returns
//
// * `Ok(String)` - The generated token string.
// * `Err(Box<dyn Error>)` - Any error that occurs during the token creation process.
pub fn create_token<T>(payload: &T, secret: &str) -> Result<String, Box<dyn Error>>
where
    T: Serialize,
{
    let payload_bytes = to_vec(payload)?;
    let signature = sign_payload(secret, &payload_bytes)?;

    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_bytes),
        URL_SAFE_NO_PAD.encode(&signature)
    ))
}

// Signs the payload using the provided secret.
//
// # Arguments
//
// * `secret` - The secret key used to sign the payload.
// * `payload` - The payload data to be signed.
//
// # Returns
//
// * `Ok(Vec<u8>)` - The generated signature.
// * `Err(Box<dyn Error>)` - Any error that occurs during the signing process.
fn sign_payload(secret: &str, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

// Verifies a token and returns the decoded payload if valid.
//
// This function decodes the token, verifies the signature, checks if the 
// token is expired, and returns the payload if everything is valid. 
// The payload is deserialized into the type `T`.
//
// # Arguments
//
// * `secret` - The secret key used to verify the token's signature.
// * `token` - The token string to be verified and decoded.
//
// # Returns
//
// * `Ok(T)` - The deserialized payload if the token is valid and not expired.
// * `Err(Box<dyn Error>)` - Any error that occurs during the verification process.
pub fn verify_token<T>(secret: &str, token: &str) -> Result<T, Box<dyn Error>>
where
    T: for<'de> Deserialize<'de> + Expirable,
{
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(Box::new(TokenError("Invalid token format".to_string())));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let signature = URL_SAFE_NO_PAD.decode(parts[1])?;

    let expected_signature = sign_payload(secret, &payload_bytes)?;
    if signature != expected_signature {
        return Err(Box::new(TokenError("Invalid token signature".to_string())));
    }

    let payload: T = from_slice(&payload_bytes)?;

    let exp_timestamp = payload.exp();
    let now_timestamp = Utc::now().timestamp();

    if exp_timestamp < now_timestamp {
        return Err(Box::new(TokenError("Token has expired".to_string())));
    }

    Ok(payload)
}

// Decodes a token and returns the payload if valid.
//
// This function decodes the token and deserializes the payload into the type `T`.
// It does not check for signature or expiration, making it suitable for use cases 
// where only the payload is needed.
//
// # Arguments
//
// * `token` - The token string to be decoded.
//
// # Returns
//
// * `Ok(T)` - The deserialized payload if the token is valid.
// * `Err(Box<dyn Error>)` - Any error that occurs during the decoding process.
pub fn decode_token<T>(token: &str) -> Result<T, Box<dyn Error>>
where
    T: for<'de> Deserialize<'de>,
{
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(Box::new(TokenError("Invalid token format".to_string())));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload: T = from_slice(&payload_bytes)?;

    Ok(payload)
}