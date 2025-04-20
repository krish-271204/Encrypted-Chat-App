import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'  # Change to server IP on LAN
PORT = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive RSA Public Key
public_pem = b""
while not public_pem.endswith(b"-----END PUBLIC KEY-----\n"):
    public_pem += client.recv(1024)

public_key = serialization.load_pem_public_key(public_pem)

# Generate and send AES key encrypted with RSA
aes_key = Fernet.generate_key()
fernet = Fernet(aes_key)

encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
client.send(encrypted_key)

# Step 3: Messaging
def receive():
    while True:
        try:
            data = client.recv(4096)
            msg = fernet.decrypt(data).decode()
            print("Peer:", msg)
        except:
            break

threading.Thread(target=receive, daemon=True).start()

while True:
    try:
        msg = input()
        if msg.lower() == "/quit":
            break
        encrypted_msg = fernet.encrypt(msg.encode())
        client.send(encrypted_msg)
    except:
        break

client.close()
