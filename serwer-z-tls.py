import socket
import ssl
import os
import logging
from pathlib import Path

#Konfiguracja podstawowego logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def start_server(host='127.0.0.1', port=8080):
    
    try:
        #Stwórz i skonfiguruj kontekst SSL
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        #Załaduj certyfikaty
        try:
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        except FileNotFoundError:
            logger.error("Nie znaleziono plików certyfikatów SSL (server.crt i server.key)")
            logger.info("Generowanie self-signed certyfikatu...")
            
            #Generowanie self-signed certyfikatu
            os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"')
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        #Stwórz socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            #Pozwól na ponowne użycie adresu
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            logger.info(f"Serwer nasłuchuje na {host}:{port}")

            
            with context.wrap_socket(sock, server_side=True) as secure_sock:
                while True:
                    try:
        
                        conn, addr = secure_sock.accept()
                        logger.info(f"Połączenie od {addr}")

                        try:
    
                            filename = conn.recv(1024).decode().strip()
                            logger.info(f"Żądanie pliku: {filename}")

                        
                            if os.path.exists(filename):
                                filesize = os.path.getsize(filename)
                                conn.send(f"{filename},{filesize}".encode())

                                #Wysyłanie pliku
                                with open(filename, 'rb') as f:
                                    sent = 0
                                    while True:
                                        data = f.read(8192)
                                        if not data:
                                            break
                                        conn.sendall(data)
                                        sent += len(data)
                                        logger.info(f"Wysłano: {sent}/{filesize} bajtów")
                                
                                logger.info(f"Plik {filename} wysłany pomyślnie")
                            else:
                                logger.warning(f"Plik {filename} nie znaleziony")
                                conn.send(b"File not found")

                        except Exception as e:
                            logger.error(f"Błąd podczas obsługi klienta: {str(e)}")
                        finally:
                            conn.close()

                    except ssl.SSLError as e:
                        logger.error(f"Błąd SSL: {str(e)}")
                    except Exception as e:
                        logger.error(f"Nieoczekiwany błąd: {str(e)}")

    except Exception as e:
        logger.error(f"Błąd krytyczny serwera: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        logger.info("Serwer zatrzymany przez użytkownika")
    except Exception as e:
        logger.error(f"Serwer zatrzymany z powodu błędu: {str(e)}")