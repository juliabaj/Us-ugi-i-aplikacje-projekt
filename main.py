import szyfrowanie
import deszyfrowanie

if __name__ == '__main__':
    option = input("Wybierz jedną z opcji:\n1. Szyfruj plik\n2. Odszyfruj plik\n")
    plik = input("Podaj pełną ścieżkę do pliku:\n")
    plik = r"{}".format(plik)
    haslo = input("Podaj hasło:\n").encode()
    if option == "1":
        szyfrowanie.encrypt_file(plik, haslo)
    if option == "2":
        deszyfrowanie.decrypt_file(plik, haslo)