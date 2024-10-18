import socket
import threading
import ssl
import os
from OpenSSL import crypto

clients = {}


#Funckja ogarniająca wielu klientów na serwerze

def handle_client(client_socket, client_address):
    try:
        client_name = client_socket.recv(1024).decode('utf-8')
        clients[client_name] = client_socket
        print(f"{client_name} connected from {client_address}")

        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    raise ConnectionResetError("Client disconnected")
                print(f"Received message from {client_name}: {message}")
                
                #Szczerze nie wiem co to szukając rozwiązania chat mi kazał takie coś napisać, nie pomogło. W teorii jeżeli wiadomość będzie PING to odesle clientowi PONG pewnie do sprawdzenia/utrzymania połączenia w dalszej częsci kodu też coś takiego zrobiłem po tym jak time out będzie miał klient
                if message == "PING":
                    client_socket.send("PONG".encode('utf-8'))
                    continue
                
                #Ta część decyduje o tym co dalej robić z wiadomością, stwierdziłem, że chyba tak bedzie najlepiej rozróżniać czy wiadomość to pytanie czy nie po prostu przeszukuje początki wiadomości na co natrafi takie podejmuje akcje  

                if message.startswith("REQUEST_FILE:"):
                    _, recipient_name, filename = message.split(':', 2)
                    if recipient_name in clients:
                        recipient_socket = clients[recipient_name]
                        confirmation_msg = f"FILE_REQUEST:{client_name} chce wyslac ci plik {filename}. Czy chcesz zaakceptowac?(tak/nie)".encode('utf-8')
                        recipient_socket.send(confirmation_msg)
                    
                        response = recipient_socket.recv(1024).decode('utf-8')
                        if response.lower() == 'tak':
                            client_socket.send("READY_TO_SEND".encode('utf-8'))
                            stream_file(client_socket, recipient_socket, filename)
                        else:
                           client_socket.send("Twoja prosba o wyslanie pliku zostala odrzucona.".encode('utf-8'))
                    else:
                        client_socket.send("Odbiorca nie dostepny".encode('utf-8'))
            
                elif message.startswith("MESSAGE:"):
                    _, recipient_name, data = message.split(':', 2)
                    if recipient_name in clients:
                        recipient_socket = clients[recipient_name]
                        recipient_socket.send(message.encode('utf-8'))
                    else:
                        client_socket.send("Odbiorca nie dostepny".encode('utf-8'))
            
                else:
                    client_socket.send("Nieprawidlowy format wiadomosci. Uzyj 'REQUEST_FILE:odbiorca:nazwa_pliku' lub 'MESSAGE:odbiorca:wiadomosc'.".encode('utf-8'))

            #O tym mówiłem przy PING
            except socket.timeout:
                print(f"Upłynął limit czasu połączenia dla {client_name}.")
                try:
                    client_socket.send("PING".encode('utf-8'))
                except:
                    raise ConnectionResetError("Failed to send keep-alive")
            except ConnectionResetError as e:
                print(f"{client_name} disconnected: {e}")
                break
            except Exception as e:
                print(f"Unexpected error for {client_name}: {e}")
                break

    except ssl.SSLError as e:
        print(f"SSL Error with {client_address}: {e}")
    except Exception as e:
        print(f"Unexpected error for {client_address}: {e}")
    finally:
        if client_name and client_name in clients:
            del clients[client_name]
        client_socket.close()
        print(f"Zamknięto połączenie dla {client_name if client_name else client_address}")

def stream_file(sender_socket, recipient_socket, filename):
    try:
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Plik {filename} nie znaleziony")
        
        filesize = os.path.getsize(filename)
        recipient_socket.send(f"FILE_INCOMING:{filename}:{filesize}".encode('utf-8'))
        
        with open(filename, 'rb') as f:
            bytes_sent = 0
            while bytes_sent < filesize:
                bytes_read = f.read(4096)
                if not bytes_read:
                    break
                recipient_socket.sendall(bytes_read)
                bytes_sent += len(bytes_read)
        
        sender_socket.send("Plik zostal wyslany pomyslnie.".encode('utf-8'))
        recipient_socket.send("FILE_TRANSFER_COMPLETE".encode('utf-8'))
    except FileNotFoundError as e:
        sender_socket.send(f"Plik nie istnieje: {str(e)}".encode('utf-8'))
    except Exception as e:
        sender_socket.send(f"Blad podczas wysylania pliku: {str(e)}".encode('utf-8'))

def create_self_signed_cert(cert_file, key_file):
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "PL"
    cert.get_subject().ST = "Poland"
    cert.get_subject().L = "Warsaw"
    cert.get_subject().O = "My Organization"
    cert.get_subject().OU = "My Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # Write the cert and key files
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

def start_server(host="127.0.0.1", port=443):
    cert_file = "server.crt"
    key_file = "server.key"
    
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("Certificate files not found. Generating self-signed certificate...")
        create_self_signed_cert(cert_file, key_file)
        print("Self-signed certificate generated.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

    
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(f"Serwer: {host}:{port}")
        
        with context.wrap_socket(server, server_side=True) as secure_server:
            while True:
                try:
                    client_socket, client_address = secure_server.accept()
                    client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
                    client_handler.start()
                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                except Exception as e:
                    print(f"Error accepting connection: {e}")

if __name__ == "__main__":
    start_server()