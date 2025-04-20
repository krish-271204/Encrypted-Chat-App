import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuration 
HOST = '127.0.0.1'  # server's IP for LAN
PORT = 5555

# Network and Encryption Setup
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive server's RSA public key
public_pem = b""
while not public_pem.endswith(b"-----END PUBLIC KEY-----\n"):
    public_pem += client.recv(1024)

server_public_key = serialization.load_pem_public_key(public_pem)

# Generate AES key and send encrypted key
aes_key = Fernet.generate_key()
fernet = Fernet(aes_key)

encrypted_key = server_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
client.send(encrypted_key)

#GUI Code
class ChatClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("🔐 Encrypted Chat (RSA + AES)")
        master.geometry("500x400")

        self.chat_display = scrolledtext.ScrolledText(master, state='disabled', wrap=tk.WORD)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(master, font=("Arial", 12))
        self.entry.pack(padx=10, pady=(0, 10), fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        self.entry.focus()

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, event=None):
        message = self.entry.get().strip()
        if message:
            try:
                encrypted_msg = fernet.encrypt(message.encode())
                client.send(encrypted_msg)
                self.display_message("You: " + message)
                self.entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send message: {e}")

    def receive_messages(self):
        while True:
            try:
                data = client.recv(4096)
                if not data:
                    break
                decrypted = fernet.decrypt(data).decode()
                self.display_message("Peer: " + decrypted)
            except Exception as e:
                break

    def display_message(self, msg):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, msg + '\n')
        self.chat_display.yview(tk.END)
        self.chat_display.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
    client.close()
