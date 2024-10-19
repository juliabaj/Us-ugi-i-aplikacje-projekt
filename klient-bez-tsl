import socket
import threading
import os
import szyfrowanie
import deszyfrowanie


def connect_to_server(host="127.0.0.1", port=8080):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
        print(f"Połączono z serwerem: {host}:{port}")
        name = input("Wpisz swoją nazwę: ")
        sock.send(name.encode('utf-8'))
        return sock, name
    except Exception as e:
        print(f"Błąd podczas łączenia z serwerem: {e}")
        raise


def send_message(sock, recipient, message):
    sock.send(f"MESSAGE:{recipient}:{message}".encode('utf-8'))


def request_file_transfer(secure_sock, recipient, filename):
    if not os.path.exists(filename):
        print(f"Plik {filename} nie istnieje.")
        return

    password = input("Podaj hasło do szyfrowania pliku: ")

    # Tworzenie wiadomości
    request_message = f"REQUEST_FILE:{recipient}:{filename}"
    print(f"Wysyłam wiadomość do serwera: {request_message}")  # Debug

    secure_sock.send(request_message.encode('utf-8'))
    response = secure_sock.recv(1024).decode('utf-8')

    if response == "READY_TO_SEND":
        send_file(secure_sock, filename, password)
    else:
        print(response)


def send_file(sock, filename, password):
    szyfrowanie.encrypt_file(filename, password)
    encrypted_filename = filename + ".enc"

    filesize = os.path.getsize(encrypted_filename)
    sock.send(f"FILE_INCOMING:{encrypted_filename}:{filesize}".encode('utf-8'))
    with open(encrypted_filename, 'rb') as f:
        while True:
            bytes_read = f.read(4096)
            if not bytes_read:
                break
            sock.sendall(bytes_read)
    print(f"Plik {encrypted_filename} wysłany pomyślnie.")


def receive_file(sock, filename, filesize, password):
    received_size = 0
    encrypted_filename = filename + ".enc"

    with open(encrypted_filename, 'w') as f:
        while received_size < filesize:
            bytes_read = sock.recv(4096)
            if not bytes_read:
                break
            f.write(bytes_read)
            received_size += len(bytes_read)

    print(f"Plik {encrypted_filename} otrzymany pomyślnie.")
    deszyfrowanie.decrypt_file(encrypted_filename, password)


def parse_message(message):
    parts = message.split(':', 2)
    if len(parts) < 2:
        return None, None, message
    elif len(parts) == 2:
        return parts[0], None, parts[1]
    else:
        return parts[0], parts[1], parts[2]


def listen_for_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            msg_type, sender, content = parse_message(message)

            if msg_type == "FILE_REQUEST":
                print(f"\n{sender} chce wysłać ci plik: {content}")
                response = input("Czy chcesz zaakceptować? (tak/nie): ").strip().lower()
                sock.send(response.encode('utf-8'))
                if response == 'tak':
                    file_info = sock.recv(1024).decode('utf-8')
                    print(f"Otrzymano informacje o pliku: {file_info}")  # Dodano do debugowania
                    _, filename, filesize = parse_message(file_info)

                    password = input("Podaj hasło do odszyfrowania pliku: ")

                    try:
                        if filename and filesize.isdigit():  # Sprawdzenie, czy filesize to liczba
                            receive_file(sock, filename, int(filesize), password)
                        else:
                            print("Otrzymano nieznane dane pliku.")
                    except ValueError:
                        print(f"Błąd konwersji: {filesize}. Upewnij się, że rozmiar pliku jest liczbą.")
            elif msg_type == "MESSAGE":
                print(f"\nWiadomość od {sender}: {content}")
            elif msg_type == "FILE_TRANSFER_COMPLETE":
                print("Zakończono przesyłanie pliku.")
            else:
                print(f"Otrzymano: {message}")

            if input("Czy chcesz kontynuować nasłuchiwanie? (tak/nie): ").strip().lower() != 'tak':
                break

        except Exception as e:
            print(f"Błąd: {e}")
            break


def main_menu(sock):
    while True:
        try:
            action = input(
                "Wpisz 'wiadomosc' do wysłania wiadomości, 'plik' do wysłania pliku, 'nasluchuj' do otrzymania wiadomości lub 'quit' do wyjścia: "
            ).lower()

            if action == 'quit':
                break
            elif action == 'wiadomosc':
                recipient = input("Podaj nazwę odbiorcy: ")
                message = input("Podaj treść wiadomości: ")
                send_message(sock, recipient, message)
            elif action == 'plik':
                recipient = input("Podaj nazwę odbiorcy: ")
                filename = input("Podaj nazwę pliku do wysłania: ")
                request_file_transfer(sock, recipient, filename)
            elif action == 'nasluchuj':
                listen_for_messages(sock)
            else:
                print("Nie ma takiej opcji, spróbuj ponownie.")

        except Exception as e:
            print(f"Błąd: {e}")
            break


if __name__ == "__main__":
    try:
        sock, name = connect_to_server()
        main_menu(sock)
    except Exception as e:
        print(f"Nie udało się wystartować klienta: {e}")
