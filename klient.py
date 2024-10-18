import socket
import ssl
import threading
import os


#Tu w ogóle dziwnie poprosiłem chata żeby mi go sam wygenerował no i wygenerował klase to w sumie do poprawienia myśle znaczy działa, ale nie wiem akurat dlaczego tak zrobił
class Client:
    def __init__(self, host="127.0.0.1", port=443):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE  
        self.context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_sock = self.context.wrap_socket(self.sock, server_hostname=host)
        
        try:
            self.secure_sock.connect((host, port))
            print(f"Połączony do: {host}:{port}")
            self.name = input("Wpisz swoją nazwę: ")
            self.secure_sock.send(self.name.encode('utf-8'))
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
            raise
        except Exception as e:
            print(f"Error connecting to server: {e}")
            raise

    def send_message(self, recipient, message):
        self.secure_sock.send(f"MESSAGE:{recipient}:{message}".encode('utf-8'))

    def request_file_transfer(self, recipient, filename):
        if not os.path.exists(filename):
            print(f"Plik {filename} nie istnieje.")
            return
        self.secure_sock.send(f"REQUEST_FILE:{recipient}:{filename}".encode('utf-8'))
        response = self.secure_sock.recv(1024).decode('utf-8')
        if response == "READY_TO_SEND":
            self.send_file(filename)
        else:
            print(response)

    #Funkcja do wysyłania pliku
    def send_file(self, filename):
        filesize = os.path.getsize(filename)
        self.secure_sock.send(f"FILE_INCOMING:{filename}:{filesize}".encode('utf-8'))
        with open(filename, 'rb') as f:
            while True:
                bytes_read = f.read(4096)
                if not bytes_read:
                    break
                self.sock.sendall(bytes_read)
        print(f"Plik {filename} wysłany pomyślnie.")

    #Funckja do otrzymuwania pliku
    def receive_file(self, filename, filesize):
        received_size = 0
        with open(filename, 'wb') as f:
            while received_size < filesize:
                bytes_read = self.sock.recv(4096)
                if not bytes_read:
                    break
                f.write(bytes_read)
                received_size += len(bytes_read)
        print(f"Plik {filename} otrzymany pomyślnie.")

    def parse_message(self, message):
        parts = message.split(':', 2)
        if len(parts) < 2:
            return None, None, message
        elif len(parts) == 2:
            return parts[0], None, parts[1]
        else:
            return parts[0], parts[1], parts[2]

    def listen(self):
        while True:
            try:
                message = self.secure_sock.recv(1024).decode('utf-8')
                msg_type, sender, content = self.parse_message(message)

                if msg_type == "FILE_REQUEST":
                    print(f"\n{sender} chce wysłać ci plik: {content}")
                    response = input("Czy chcesz zaakcpetować? (tak/nie): ")
                    self.secure_sock.send(response.encode('utf-8'))
                    if response.lower() == 'tak':
                        file_info = self.sock.recv(1024).decode('utf-8')
                        _, filename, filesize = self.parse_message(file_info)
                        if filename and filesize:
                            self.receive_file(filename, int(filesize))
                        else:
                            print("Nie znane dane pliku otrzymane.")
                elif msg_type == "MESSAGE":
                    print(f"\nWiadomość {sender}: {content}")
                elif msg_type == "FILE_TRANSFER_COMPLETE":
                    print("Zakończono przesyłanie pliku.")
                else:
                    print(f"Received: {message}")
            except ssl.SSLError as e:
                print(f"SSL Error: {e}")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break


    def run(self):
        listener = threading.Thread(target=self.listen)
        listener.start()

        while True:
            try:
                action = input("Wpisz 'wiadomosc' do wysłania wiadomości, 'plik' do wysłania pliku, lub 'quit' do wyjścia: ")
                if action.lower() == 'quit':
                    break
                elif action.lower() == 'wiadomosc':
                    recipient = input("Enter recipient's name: ")
                    message = input("Enter your message: ")
                    self.send_message(recipient, message)
                elif action.lower() == 'plik':
                    recipient = input("Enter recipient's name: ")
                    filename = input("Enter the filename to send: ")
                    self.request_file_transfer(recipient, filename)
                else:
                    print("Nie ma takiej opcji, spróbuj jeszcze raz")
            except ssl.SSLError as e:
                print(f"SSL Error: {e}")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break

        self.secure_sock.close()

if __name__ == "__main__":
    try:
        client = Client()
        client.run()
    except Exception as e:
        print(f"Nie udało się wystartować klienta: {e}")