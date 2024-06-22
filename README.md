# Encryption/Decryption API

This project provides a REST API for cryptographic operations using Rust and Rocket. The API allows users to create user keys, encrypt messages, and decrypt messages using the `x25519_dalek` and `aes_gcm` crates for secure cryptographic operations. The encryption and decryption processes utilize the Diffie-Hellman key exchange method to securely derive a shared secret between two parties.

## Features

- **Create User Key**: Generates a new user key pair (public and secret keys) using Diffie-Hellman key exchange.
- **Encrypt Message**: Encrypts a message using a shared secret derived from Diffie-Hellman key exchange.
- **Decrypt Message**: Decrypts a message using a shared secret derived from the Diffie-Hellman key exchange.

## Endpoints

### Create User Key

- **Endpoint**: `/create_user_key`
- **Method**: `POST`
- **Description**: Generates a new user key pair.
- **Response**:
  ```json
  {
    "public_key": [byte array],
    "user_secret": [byte array]
  }
    ```

### Encrypt Message
- **Endpoint**: `/encrypt`
- **Method**: `POST`
- **Description**: Encrypts a message.
- **Request Body**:
  ```json
    {
    "nonce": "12_byte_string",
    "message": "your_message",
    "other_public_key": [byte array],
    "user_secret": [byte array]
    }
    ```

- **Response**:
  ```json
    {
    "ciphertext": [byte array]
    }
    ```

### Decrypt Message
- **Endpoint**: `/decrypt`
- **Method**: `POST`
- **Description**: Decrypts a message.
- **Request Body**:
  ```json
    {
  "ciphertext": [byte array],
  "other_public_key": [byte array],
  "user_secret": [byte array],
  "nonce": "12_byte_string"
    }
    ```

- **Response**:
  ```json
    {
        "message": "your_decrypted_message"
    }
    ```

## Requirements
- Rust 1.76 or later
- cargo

## Setup

### 1. Clone the repository
gh repo clone afgonzalez-dev/EnigmaChat
cd EnigmaChat
### 2. cargo build

## Running the Server
``` cargo run ```

## Create User Key
``` curl -X POST http://localhost:8000/create_user_key ```

## Encrypt Message
``` curl -X POST http://localhost:8000/encrypt -H "Content-Type: application/json" -d '{
  "nonce": "123456789012",
  "message": "Hello, World!",
  "other_public_key": [48, 165, ...],
  "user_secret": [106, 54, ...]
}' ```

## Decrypt Message
``` curl -X POST http://localhost:8000/decrypt -H "Content-Type: application/json" -d '{
  "ciphertext": [99, 34, ...],
  "other_public_key": [48, 165, ...],
  "user_secret": [106, 54, ...],
  "nonce": "123456789012"
}' ```

Project Structure
```
enigmachat/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── user_key.rs
│   │   ├── encrypt.rs
│   │   ├── decrypt.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── key_management.rs
│   │   ├── encryption.rs
│   │   ├── decryption.rs
│   └── catchers/
│       ├── mod.rs
│       ├── validation.rs
└── src/error.rs
```
