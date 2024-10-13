from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Funkcja do wygenerowania klucza
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

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
    with open(file_path + ".enc", 'wb') as f_enc:
        f_enc.write(salt + iv + encrypted_data)

    print("Plik został zaszyfrowany i zapisany jako:", file_path + ".enc")

# Funkcja do odszyfrowania pliku
def decrypt_file(encrypted_file_path, password):
    try:
        with open(encrypted_file_path, 'rb') as f_enc:
            file_data = f_enc.read()

        salt = file_data[:16]  # pierwszy blok to sól
        iv = file_data[16:32]  # drugi blok to IV
        encrypted_data = file_data[32:]  # reszta to zaszyfrowane dane

        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Usuń padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        original_file_path = encrypted_file_path.replace(".enc", "")  # przywracanie poprzedniej nazwy
        with open(original_file_path, 'wb') as f_dec:
            f_dec.write(decrypted_data)

        print("Plik został odszyfrowany i zapisany jako:", original_file_path)
    except:
        print("Odszyfrowanie nie powiodło się.")


