
# CrabToken

An in house alternative to JWT and Paseto


## Documentation

[Docs.rs](https://docs.rs/crabtoken)

[Crates.io](https://crates.io/crates/crabtoken)

[Github.com](https://github.com/Stipulations/CrabToken)

## Features

- Create and verify JWT-like tokens with base64url encoding
- HMAC-SHA256 signature generation and verification
- Expiration validation for tokens
- Payload serialization and deserialization using `serde`
- Flexible token payload structure with `Expirable` trait for expiration handling
- Cross-platform compatibility

## Contributing

Contributions are always welcome!

See something that should be done better or that i was stupid enought to miss, please make a fork and request a PR and once approved ill pull to main.

## Basic Usage

```rust
use crabtoken::{create_token, decode_token, verify_token, Expirable};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{thread, time};

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomPayload {
    pub user_id: String,
    pub exp: i64,
    pub data: String,
}

impl Expirable for CustomPayload {
    fn exp(&self) -> i64 {
        self.exp
    }
}

fn main() {
    let secret = "Just a cat eating tacos";

    let payload = CustomPayload {
        user_id: "user123".to_string(),
        exp: Utc::now().timestamp() + 10,
        data: "Custom data!".to_string(),
    };

    let token = create_token(&payload, secret).unwrap();
    println!("Generated Token: {}", token);

    match verify_token::<CustomPayload>(secret, &token) {
        Ok(verified_payload) => println!("{:?}", verified_payload),
        Err(e) => println!("{}", e),
    }

    match decode_token::<CustomPayload>(&token) {
        Ok(decoded_payload) => {
            println!("Decoded Payload:");
            println!("User ID: {}", decoded_payload.user_id);
            println!("Expiration: {}", decoded_payload.exp);
            println!("Data: {}", decoded_payload.data);
        }
        Err(e) => println!("Error decoding token: {}", e),
    }

    println!("Sleeping for 12 seconds to let the token expire...");
    thread::sleep(time::Duration::from_secs(12));

    match verify_token::<CustomPayload>(secret, &token) {
        Ok(verified_payload) => println!("{:?}", verified_payload),
        Err(e) => println!("{}", e),
    }
}
```


## Used By

This project is used by the following companies:

- not a soul cuz why would they?
- me maybe one day? perhaps after i get my SaaS started but thats eta 2050


## License

[MIT](https://choosealicense.com/licenses/mit/)