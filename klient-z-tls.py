import socket
import ssl
import os
from pathlib import Path
import logging
import hashlib
from tqdm import tqdm
import szyfrowanie
import deszyfrowanie
import subprocess
import re

#konfiguracja podstawowego logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_available_users(mac_list):
    available_users = {}
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        lines = output.splitlines()
        
        for name, mac in mac_list.items():
            for line in lines:
                if mac.lower() in line.lower():
                    ip_address = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if ip_address:
                        available_users[name] = ip_address.group(0)
                        break
        return available_users
    except Exception as e:
        logger.error(f"Błąd podczas sprawdzania dostępnych użytkowników: {str(e)}")
        return {}
    

def setup_client_ssl_context() -> ssl.SSLContext:
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return context
    except Exception as e:
        logger.error(f"Failed to setup SSL context: {e}")
        raise

def setup_sender_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:

    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return context
    except Exception as e:
        logger.error(f"Failed to setup sender SSL context: {e}")
        raise

def calculate_file_hash(filepath: str) -> str:
    #Przelicza hash dla pliku
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def send_file(
    file_path: str,
    target_ip: str,
    port: int = 8080,
    cert_file: str = "server.crt",
    key_file: str = "server.key",
    buffer_size: int = 8192
) -> bool:


    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return False

    context = setup_sender_ssl_context(cert_file, key_file)
    file_hash = calculate_file_hash(file_path)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((target_ip, port))
            logger.info(f"Łączenie z {target_ip}:{port}")

            with context.wrap_socket(sock, server_side=False, server_hostname=target_ip) as secure_sock:
                
                logger.info(f"Połączono do {target_ip}")

                try:
                    file_name = os.path.basename(file_path)
                    file_size = os.path.getsize(file_path)

                    #Wysyłanie metadanych pliku i hasha
                    metadata = f"{file_name},{file_size},{file_hash}"
                    secure_sock.send(metadata.encode())

                    with open(file_path, 'rb') as file:
                        with tqdm(total=file_size, unit='B', unit_scale=True) as pbar:
                            sent = 0
                            while sent < file_size:
                                data = file.read(buffer_size)
                                if not data:
                                    break
                                secure_sock.sendall(data)
                                sent += len(data)
                                pbar.update(len(data))

                    logger.info(f"Wysłany pomyślnie: {file_name}")
                    return True

                except Exception as e:
                    logger.error(f"Błąd podczas wysyłania: {e}")
                    return False
                finally:
                    secure_sock.close()

    except Exception as e:
        logger.error(f"Błąd połączenia: {e}")
        return False


def receive_file(
    port: int = 8080,
    timeout: int = 600,
    buffer_size: int = 8192
) -> bool:

    context = setup_client_ssl_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(1)
            sock.settimeout(timeout)
            logger.info(f"Oczekiwanie na połączenie na porcie {port}")

            while True:
                    conn, addr = sock.accept()
                    logger.info(f"Połączenie przychodzące od {addr}")

                    with context.wrap_socket(conn, server_side=True) as secure_sock:
                        try:
                            response = secure_sock.recv(1024).decode()
                            filename, filesize, expected_hash = response.split(",")
                            filesize = int(filesize)

                            logger.info(f"Otrzymywanie pliku: {filename} ({filesize} bytów)")

                            output_path = Path("downloads") / filename
                            output_path.parent.mkdir(exist_ok=True)

                            with open(output_path, 'wb') as f:
                                with tqdm(total=filesize, unit='B', unit_scale=True) as pbar:
                                    received = 0
                                    while received < filesize:
                                        data = secure_sock.recv(min(buffer_size, filesize - received))
                                        if not data:
                                            break
                                        f.write(data)
                                        received += len(data)
                                        pbar.update(len(data))

                            haslo = (input("Podaj hasło aby odszyfrować plik: ").encode())
                            path = output_path
                            print(f"To jest ścieżka do pliku {path}")
                            path = r"{}".format(path)
                            deszyfrowanie.decrypt_file(path, haslo)
                            #Weryfikowanie hasha pliku
                            received_hash = calculate_file_hash(str(output_path))
                            if received_hash != expected_hash:
                                logger.error("File integrity check failed!")
                                os.remove(output_path)
                                return False

                            logger.info(f"Pomyślnie otrzymano plik: {filename}")
                            return True

                        except Exception as e:
                            logger.error(f"Błąd podczas otrzymywania pliku: {e}")
                            return False

    except Exception as e:
        logger.error(f"Błąd połączenia: {e}")
        return False

def main():
    mac_list = {"Gabrys2":"F4-A4-75-06-AF-72" }
    while True:
        print("\nKlient do zaszyfrowanego przesyłu plików")
        print("1. Wyślij plik")
        print("2. Otrzymaj plik")
        print("q. Quit")
        
        choice = input("\nWybierz: ").lower()
        
        if choice == '1':
            available_users = get_available_users(mac_list)
            if not available_users:
                print("Nie ma dostępnych użytkowników")
                continue
            print("\nDostępni użytkownicy:")
            for i, (name, ip) in enumerate(available_users.items(),1 ):
                print(f" {i}. {name}({ip})")

            try:
                user_choice = int(input("\nWybierz odbiorce: "))
                if user_choice < 1 or user_choice > i:
                    print("Nieprawidłowy wybór")
                    continue
                seleted_user = list(available_users.items())[user_choice - 1]
                target_ip = seleted_user[1]


                file_path = input("Podaj ścieżkę do pliku: ")
                file_path = file_path
                password = (input("Zaszyfruj plik hasłem: ").encode())
                szyfrowanie.encrypt_file(file_path, password)
                enc_file_path = file_path + ".enc"
            
                print(f"Wysyłanie pliku do użykownika {seleted_user[0]}")
                port = 8080
                send_file(enc_file_path, target_ip, port)
            except ValueError:
                print("Nieprawidłowy wybór")
                continue
            except Exception as e:
                logger.error(f"Wystąpił błąd: str{e}")
                continue 
            
        
        elif choice == '2':
            port = int(8080)
            receive_file(port)
            
        
        elif choice == 'q':
            print("Exiting...")
            break
        
        else:
            print("Nie ma takiej opcji, spróbuj jeszcze raz.")

if __name__ == "__main__":
    main()