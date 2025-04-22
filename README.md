# Encrypted Chat Application

A simple chat application with RSA and AES encryption for secure communication.

## Features

- RSA encryption for secure key exchange
- AES encryption for message content
- End-to-end encrypted messaging
- Simple GUI interface

## Security Implementation

- RSA 2048-bit keys for asymmetric encryption during initial handshake
- AES 128-bit keys for symmetric encryption of messages
- Unique session keys for each client connection
- Secure key exchange protocol

## Installation

1. Clone this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Start the Server

```bash
python server.py
```

The server will start on localhost (127.0.0.1) port 5555 by default.

### Start the Client

```bash
python client.py
```

Multiple clients can connect to the same server.

## How it Works

1. Client and server generate RSA key pairs on startup
2. During connection:
   - Client and server exchange public RSA keys
   - Client generates an AES session key
   - Client encrypts the session key with the server's public RSA key and sends it
   - All subsequent messages are encrypted with AES using the session key
3. Messages in the chat are encrypted end-to-end

