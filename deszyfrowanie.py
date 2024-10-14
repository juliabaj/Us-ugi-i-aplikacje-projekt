from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from generator import generate_key

# Funkcja do odszyfrowania pliku
def decrypt_file(encrypted_file_path, password):
    try:
        with open(encrypted_file_path, 'rb') as enc_file:
            file_data = enc_file.read()

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
        with open(original_file_path, 'wb') as file:
            file.write(decrypted_data)

        print("Plik został odszyfrowany i zapisany jako:", original_file_path)
    except:
        print("Odszyfrowanie nie powiodło się.")
