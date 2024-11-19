import socket
import ssl
import os
from pathlib import Path
import logging
import threading
from tqdm import tqdm
import ipaddress
import time
import struct
import subprocess
import re
import szyfrowanie
import deszyfrowanie


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

global status
status = True

def get_available_users(mac_list):
    available_users = {}
    try:
        #w tle odplamy arpa co by sprawdzić adresy mac
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

class P2PFileTransfer:
    #Dałem limit 1GB na wysłanie pliku
    MAX_FILE_SIZE = 1024 * 1024 * 1024 
    CHUNK_SIZE = 4096 
    BUFFER_SIZE = 8192
    
    def __init__(self, listen_port=8000):
        self.listen_port = listen_port
        self.running = False
        self.server_socket = None
        self.ssl_context = self._setup_ssl_context()
        
    def _setup_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        except (FileNotFoundError, ssl.SSLError) as e:
            logger.error(f"Niepowiodło się załadownie certyfikatu: {e}")
            raise
        return context


    #Na początku dołącza długość, żeby potem przy odbieraniu wiedział ile ma odebrać bo były problemy i nie chciało całych plików odbierać
    def _send_with_length_prefix(self, sock, data):
        
        length = len(data)
        sock.sendall(struct.pack('!I', length))
        sock.sendall(data)

    #No tutaj odbiera i sobie tego prefixa rozpakowywuje
    def _recv_with_length_prefix(self, sock):
        
        length_data = self._recv_all(sock, 4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        return self._recv_all(sock, length)

    def _recv_all(self, sock, n):
        
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(min(n - len(data), self.BUFFER_SIZE))
            if not packet:
                return None
            data.extend(packet)
        return data

    def start_listening(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Zwiększamy bufor
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            self.server_socket.bind(('0.0.0.0', self.listen_port))
            self.server_socket.listen(5)
            self.running = True
            
            listen_thread = threading.Thread(target=self._listen_for_connections)
            listen_thread.daemon = True
            listen_thread.start()
            
            logger.info(f"Nasłuchiwanie na porcie {self.listen_port}")
        except Exception as e:
            logger.error(f"Niepowiodło się rozpoczęcie nasłuchiwania: {e}")
            raise
        
    def _listen_for_connections(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(60) 
                secure_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                logger.info(f"Połączenie przychodzące {address}")
                
                client_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(secure_client, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Błąd zaakecptowania połączenia: {e}")
                    time.sleep(1) 
                    
    def _handle_client_connection(self, client_socket, address):
        try:  
            command = self._recv_with_length_prefix(client_socket)
            if not command:
                return
            command = command.decode('utf-8').strip()
            
            if command.startswith("SEND"):
                self._receive_file(client_socket)
            else:
                logger.warning(f"Nieznana komenda wysłana przez {address}: {command}")
                
        except Exception as e:
            logger.error(f"Błąd utrzymywania połączenia z {address}: {e}")
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception:
                pass

    def send_file(self, filepath, target_ip, target_port):
        if not os.path.exists(filepath):
            logger.error("Plik nie istnieje")
            return False
            
        if not self._validate_ip(target_ip):
            logger.error("Nieznany adres IP")
            return False
            
            
        file_size = os.path.getsize(filepath)
        if file_size > self.MAX_FILE_SIZE:
            logger.error(f"Plik jest za duży. Maksymalny rozmiar: {self.MAX_FILE_SIZE}")
            return False
            
        secure_sock = None
        try:
            client_context = ssl.create_default_context()
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            
            sock.connect((target_ip, target_port))
            secure_sock = client_context.wrap_socket(sock, server_hostname=target_ip)
        
            #Tutaj wysyłamy mu, że tak powiem komende i informacje o pliku, żeby było wiadome, że wysyłamy
            self._send_with_length_prefix(secure_sock, "SEND".encode('utf-8')) 
            file_name = os.path.basename(filepath)
            file_info = f"{file_name}|{file_size}".encode('utf-8')
            self._send_with_length_prefix(secure_sock, file_info)
            
            #Wysyłanie pliku tutaj jest
            with open(filepath, 'rb') as f:
                with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Wysyłanie {file_name}") as pbar:
                    while True:
                        chunk = f.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        self._send_with_length_prefix(secure_sock, chunk)
                        
                        ack = secure_sock.recv(1)
                        if not ack or ack != b'1':
                            raise RuntimeError("Nie udało się uzyskać potwierdzenia")
                            
                        pbar.update(len(chunk))
                        
            logger.info(f"Plik {file_name} wysłany pomyślnie")
            return True
            
        except Exception as e:
            logger.error(f"Błąd podczas przesyłu pliku: {str(e)}")
            return False
        finally:
            if secure_sock:
                try:
                    secure_sock.shutdown(socket.SHUT_RDWR)
                    secure_sock.close()
                except Exception:
                    pass
                    
    def _receive_file(self, client_socket):
        global status
        try:
            status = False
            file_info = self._recv_with_length_prefix(client_socket)
            if not file_info:
                logger.error("Nie otrzymano informacji o pliku")
                return
                
            file_info = file_info.decode('utf-8')
            filename, filesize = file_info.split('|')
            filesize = int(filesize)
            
            if filesize > self.MAX_FILE_SIZE:
                logger.error(f"Plik jest za duży. Maksymalny rozmiar: {self.MAX_FILE_SIZE}")
                return
                
            if not filename or '/' in filename or '\\' in filename:
                logger.error("Nieznana nazwa pliku")
                return
                
            download_path = Path("downloads")
            download_path.mkdir(exist_ok=True)


            with open(download_path / filename, 'wb') as f:
                with tqdm(total=filesize, unit='B', unit_scale=True, desc=f"Receiving {filename}") as pbar:
                    received = 0
                    while received < filesize:
                        chunk = self._recv_with_length_prefix(client_socket)
                        if not chunk:
                            raise RuntimeError("Połączenie zostało przerwane przed końcem wysyłania. ")
                            
                        #Wysłane potwierdzenie
                        client_socket.send(b'1')
                        
                        f.write(chunk)
                        received += len(chunk)
                        pbar.update(len(chunk))
                        
            logger.info(f"Plik {filename} otrzymany pomyślnie")
            output_path = Path("downloads") / filename

            path = output_path
            print(f"To jest ścieżka do pliku {path}")

            print("Naciśnij enter, aby przejść dalej")

            path = r"{}".format(path)
            decryption = False
            try_again = 3
            while not decryption and try_again > 0:
                password = (input("Podaj hasło aby odszyfrować plik: ").encode())
                decryption = deszyfrowanie.decrypt_file(path, password)
                if decryption:
                    time.sleep(2)
                    break
                try_again -= 1
                if try_again > 0:
                    print(f"Liczba prób: {try_again}")
                    retry = input("Czy chcesz spróbować ponowanie(t/n): ").lower()
                    if retry != "t":
                        break 
                else:
                    continue 
            status = True
        except Exception as e:
            logger.error(f"Błąd podczas odbierania pliku: {str(e)}")
            status = True
            raise
            

    def _validate_ip(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
            
    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Błąd zamykania socketu: {e}")

def main():
    global status
    p2p = P2PFileTransfer(listen_port=8000)
    p2p.start_listening()
    
    mac_list = {"Gabrys2":"f4-a4-75-06-af-72",
                "Gabrys":"dc-71-96-1e-9c-59"}

    try:
        while True:
            if status:
                print("\nZaszyfrowane wysyłanie pliku")
                print("1. Wyślij plik")
                print("q. Quit")
            
                choice = input("\nWybierz opcję: ").lower()

                if choice == '1':
                    status = False
                    available_user = get_available_users(mac_list)
                    print(f"Dostepni uzytkownicy: {available_user}")
                    user = input("Wpisz nazwe użytkonika do, którego chcesz wysłać plik: ")
                    if user in available_user:
                        target_ip = available_user[user]
                        print(f"Adres IP użytkownika {user} to: {target_ip}")
                    else:
                        print("Podany użytkownik nie jest dostępny")
                        continue
                
                    target_port = 8000
                    file_path = input("Podaj ścieżkę do pliku: ")
                    password = (input("Zaszyfruj plik hasłem: ").encode())
                    szyfrowanie.encrypt_file(file_path, password)
                    enc_file_path = file_path + ".enc"
                
                    if os.path.exists(file_path):
                        p2p.send_file(enc_file_path, target_ip, target_port)
                        status = True
                    else:
                        print("Plik nie istnieje")
                        status = True
                    
                elif choice == 'q':
                    print("Zamykanie kleinta...")
                    break
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nZamykanie klienta...")
    finally:
        p2p.stop()

if __name__ == "__main__":
    main()