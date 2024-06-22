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
