import socket
import threading
import os

clients = {}

# Funkcja obsługująca wielu klientów na serwerze
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

                if message == "PING":
                    client_socket.send("PONG".encode('utf-8'))
                    print(f"Sent PONG to {client_name}")  # Debug
                    continue

                if message.startswith("REQUEST_FILE:"):
                    print(f"{client_name} requested to send file: {message}")  # Debug
                    try:
                        _, recipient_name, filename = message.split(':', 2)
                        print(f"Parsed request file - recipient: {recipient_name}, filename: {filename}")  # Debug
                        if recipient_name in clients:
                            print(f"Forwarding file request from {client_name} to {recipient_name}.")  # Debug
                            recipient_socket = clients[recipient_name]
                            confirmation_msg = f"FILE_REQUEST:{client_name} chce wyslac ci plik {filename}. Czy chcesz zaakceptowac?(tak/nie)".encode('utf-8')
                            recipient_socket.send(confirmation_msg)

                            response = recipient_socket.recv(1024).decode('utf-8')
                            print(f"{recipient_name} response to file request: {response}")  # Debug
                            if response.lower() == 'tak':
                                client_socket.send("READY_TO_SEND".encode('utf-8'))
                                print(f"Sending file {filename} from {client_name} to {recipient_name}.")  # Debug
                                stream_file(client_socket, recipient_socket, filename)
                            else:
                                client_socket.send("Twoja prosba o wyslanie pliku zostala odrzucona.".encode('utf-8'))
                                print(f"{recipient_name} rejected the file request from {client_name}.")  # Debug
                        else:
                            client_socket.send("Odbiorca nie dostepny".encode('utf-8'))
                            print(f"Recipient {recipient_name} is not available.")  # Debug
                    except ValueError as ve:
                        print(f"ValueError while processing request: {ve}")  # Debug
                        client_socket.send("Nieprawidlowy format wiadomosci. Uzyj 'REQUEST_FILE:odbiorca:nazwa_pliku'.".encode('utf-8'))

                elif message.startswith("MESSAGE:"):
                    print(f"Processing message from {client_name}.")  # Debug
                    _, recipient_name, data = message.split(':', 2)
                    if recipient_name in clients:
                        recipient_socket = clients[recipient_name]
                        recipient_socket.send(message.encode('utf-8'))
                        print(f"Forwarded message to {recipient_name}: {data}")  # Debug
                    else:
                        client_socket.send("Odbiorca nie dostepny".encode('utf-8'))
                        print(f"Recipient {recipient_name} is not available.")  # Debug

                else:
                    print(f"Invalid message format from {client_name}: {message}")  # Debug
                    client_socket.send("Nieprawidlowy format wiadomosci. Uzyj 'REQUEST_FILE:odbiorca:nazwa_pliku' lub 'MESSAGE:odbiorca:wiadomosc'.".encode('utf-8'))

            except socket.timeout:
                print(f"Upłynął limit czasu połączenia dla {client_name}.")
                try:
                    client_socket.send("PING".encode('utf-8'))
                    print(f"Sent PING to {client_name}")  # Debug
                except:
                    raise ConnectionResetError("Failed to send keep-alive")
            except ConnectionResetError as e:
                print(f"{client_name} disconnected: {e}")
                break
            except Exception as e:
                print(f"Unexpected error for {client_name}: {e}")
                break

    except Exception as e:
        print(f"Unexpected error for {client_address}: {e}")
    finally:
        if client_name and client_name in clients:
            del clients[client_name]
            print(f"Removed {client_name} from clients.")  # Debug
        client_socket.close()
        print(f"Zamknięto połączenie dla {client_name if client_name else client_address}")

def stream_file(sender_socket, recipient_socket, filename):
    try:
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Plik {filename} nie znaleziony")

        filesize = os.path.getsize(filename)
        recipient_socket.send(f"FILE_INCOMING:{filename}:{filesize}".encode('utf-8'))
        print(f"Sending file info to recipient: {filename}, size: {filesize} bytes.")  # Debug

        with open(filename, 'rb') as f:
            bytes_sent = 0
            while bytes_sent < filesize:
                bytes_read = f.read(4096)
                if not bytes_read:
                    break
                recipient_socket.sendall(bytes_read)
                bytes_sent += len(bytes_read)
                print(f"Sent {bytes_sent} of {filesize} bytes.")  # Debug

        sender_socket.send("Plik zostal wyslany pomyslnie.".encode('utf-8'))
        recipient_socket.send("FILE_TRANSFER_COMPLETE".encode('utf-8'))
        print(f"File {filename} sent successfully.")

    except Exception as e:
        print(f"Błąd podczas przesyłania pliku: {e}")
        recipient_socket.send("Wystąpił błąd podczas przesyłania pliku.".encode('utf-8'))

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 8080))
    server_socket.listen(5)
    print("Serwer nasłuchuje na porcie 8080...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")  # Debug
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
    except KeyboardInterrupt:
        print("Serwer zatrzymany.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
