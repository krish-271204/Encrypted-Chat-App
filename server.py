# Server.py
import socket
import threading
import time
from datetime import datetime
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
from Crypto.Random import get_random_bytes

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
        # Client information storage
        self.clients = {}  
        
        # Encryption storage
        self.public_key, self.private_key = rsa.newkeys(2048)
        self.client_keys = {}  # socket: public_key
        self.session_keys = {}  # socket: session_key
        
    def encrypt_message(self, message, client_socket):
        """Encrypt a message using AES with the client's session key"""
        if client_socket not in self.session_keys:
            return None
            
        session_key = self.session_keys[client_socket]
        iv = get_random_bytes(16)  # Generate random IV for each message
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Combine IV and ciphertext for transmission
        encrypted_data = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        return json.dumps(encrypted_data)
        
    def decrypt_message(self, encrypted_json, client_socket):
        """Decrypt a message using AES with the client's session key"""
        if client_socket not in self.session_keys:
            return None
            
        try:
            encrypted_data = json.loads(encrypted_json)
            iv = base64.b64decode(encrypted_data['iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            session_key = self.session_keys[client_socket]
            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
        
    def broadcast(self, message, sender_socket=None):
        """Send message to all connected clients except the sender"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # If the message is from a client (not a system message)
        if sender_socket and sender_socket in self.clients:
            sender_name = self.clients[sender_socket]
            formatted_message = f"[{timestamp}] {sender_name}: {message}"
        else:
            formatted_message = f"[{timestamp}] {message}"
            
        print(f"Broadcasting: {formatted_message}")
        
        # List of clients to remove after broadcasting
        clients_to_remove = []
        
        # Send to all clients
        for client_socket, nickname in list(self.clients.items()):
            # Don't send message back to the sender
            if client_socket != sender_socket:
                try:
                    # All messages are encrypted with client's session key
                    if client_socket in self.session_keys:
                        encrypted_msg = self.encrypt_message(formatted_message, client_socket)
                        client_socket.send(encrypted_msg.encode('utf-8'))
                except:
                    # Mark for removal but don't modify dictionary during iteration
                    clients_to_remove.append(client_socket)
        
        # Now remove any failed clients
        for client_socket in clients_to_remove:
            self._remove_client(client_socket)
                
    def _remove_client(self, client_socket):
        """Internal method to remove a client"""
        if client_socket in self.clients:
            nickname = self.clients[client_socket]
            print(f"Removing client: {nickname}")
            del self.clients[client_socket]
            
            # Remove encryption keys
            if client_socket in self.client_keys:
                del self.client_keys[client_socket]
            if client_socket in self.session_keys:
                del self.session_keys[client_socket]
                
            try:
                client_socket.close()
            except:
                pass
            
            # Notify others that a client left
            # We don't pass the socket to broadcast since it's already removed
            self.broadcast(f"{nickname} left the chat")
            
    def handle_client(self, client_socket, address):
        """Handle a client connection"""
        try:
            # Get nickname
            nickname = client_socket.recv(1024).decode('utf-8')
            
            # Exchange encryption keys
            # Send server's public key
            client_socket.send(self.public_key.save_pkcs1())
            
            # Receive client's public key
            client_key_pem = client_socket.recv(4096)
            client_public_key = rsa.PublicKey.load_pkcs1(client_key_pem)
            self.client_keys[client_socket] = client_public_key
            
            # Receive encrypted session key
            encrypted_session_key = client_socket.recv(4096)
            session_key = rsa.decrypt(encrypted_session_key, self.private_key)
            self.session_keys[client_socket] = session_key
            
            # Store client information
            self.clients[client_socket] = nickname
            print(f"New client connected: {nickname} from {address}")
            print(f"Secure connection established with {nickname}")
            
            # Welcome the client - this needs to be encrypted too
            welcome = f"Welcome to the chat, {nickname}!"
            encrypted_welcome = self.encrypt_message(welcome, client_socket)
            client_socket.send(encrypted_welcome.encode('utf-8'))
            
            # Announce the new client to others
            self.broadcast(f"{nickname} joined the chat")
            
            # Process client messages
            while True:
                try:
                    encrypted_message = client_socket.recv(4096).decode('utf-8')
                    if encrypted_message:
                        # Decrypt the message
                        message = self.decrypt_message(encrypted_message, client_socket)
                        if message:
                            print(f"Message from {nickname}: {message}")
                            self.broadcast(message, client_socket)
                    else:
                        # Client disconnected
                        break
                except:
                    # Connection error
                    break
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        
        # Clean up when the client leaves
        self._remove_client(client_socket)
            
    def start(self):
        """Start the server"""
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        print("Using RSA for key exchange and AES for message encryption")
        
        try:
            while True:
                # Accept client connections
                client_socket, address = self.server_socket.accept()
                print(f"New connection from {address}")
                
                # Start a thread to handle this client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            # Close the server socket
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            self.server_socket.close()
            print("Server closed")
            
if __name__ == "__main__":
    server = ChatServer()
    server.start()
