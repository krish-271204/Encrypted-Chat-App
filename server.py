
---

### 📄 `server.py`

```python
import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '0.0.0.0'
PORT = 5555

clients = []
fernet_keys = {}

# RSA Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def broadcast(msg, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(msg)
            except:
                client.close()
                clients.remove(client)

def handle_client(client):
    # Send public RSA key
    client.send(public_pem)

    #  Receive encrypted AES key
    encrypted_key = client.recv(512)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    fernet = Fernet(aes_key)
    fernet_keys[client] = fernet

    print("[+] Client connected and key exchange complete.")

    while True:
        try:
            encrypted_msg = client.recv(4096)
            if not encrypted_msg:
                break
            decrypted_msg = fernet.decrypt(encrypted_msg)
            print("Message:", decrypted_msg.decode())
            broadcast(encrypted_msg, client)
        except:
            break

    client.close()
    clients.remove(client)
    print("[-] Client disconnected")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[+] Server started on {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        clients.append(client)
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    start_server()
