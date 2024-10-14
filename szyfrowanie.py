from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from generator import generate_key

# Funkcja do szyfrowania pliku multimedialnego
def encrypt_file(file_path, password):
    salt = os.urandom(16)  # losowa sól
    key = generate_key(password, salt)

    iv = os.urandom(16)  # inicjalizacyjny wektor dla trybu CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Padding danych wejściowych, aby były wielokrotnością 16 bajtów (wymagane przez AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Zapisz zaszyfrowany plik z solą i IV
    with open(file_path + ".enc", 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

    print("Plik został zaszyfrowany i zapisany jako:", file_path + ".enc")



