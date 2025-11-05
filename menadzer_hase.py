import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

username = "mistrz"
# generuje sól


def generate_salt():
    return os.urandom(16)

def generate_salt2():
    return get_random_bytes(16)
# hashuje hasło


def hash_password(password, salt):
    salted_password = password.encode('utf-8') + salt
    sha256_hash = hashlib.sha256()
    sha256_hash.update(salted_password)
    return sha256_hash.hexdigest()


# sprawdzam czy istnieje hasło mistrza
def check_database_existence(database_name):
    return os.path.exists(database_name)

# wyszukuje soli


def get_salt_by_username(username):
    conn = sqlite3.connect('mistrz_oryginał.db')
    cursor = conn.cursor()

    cursor.execute('SELECT salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    conn.close()

    if result:
        return bytes(result[0])
    else:
        return None

# weryfikowanie hasła mistrza


def verify_password(password):
    salt = get_salt_by_username(username)
    if salt:
        hashed_password = hash_password(password, salt)
        conn = sqlite3.connect('mistrz_oryginał.db')
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        result = cursor.fetchone()

        conn.close()

        return result[0] == 1
    else:
        return False

# tworze hasło mistrza


if check_database_existence("mistrz_oryginał.db") == False:
    haslo_mistrza1 = input("Podaj hasło do menadżera haseł (Po utworzeniu tego hasła będziesz musiał je zawsze podawać w celu ujawnienia innych haseł!): ")
    haslo_mistrza2 = input("Potwierdz hasło: ")
    while haslo_mistrza1 != haslo_mistrza2:
        print("Hasła się nie zgadzają. Spróbuj ponownie.")
        haslo_mistrza1 = input(
            "Podaj hasło do menadżera haseł (po utworzeniu tego hasła będziesz musiał je zawsze podawać w celu ujawnienia innych haseł!): ")
        haslo_mistrza2 = input("Potwierdz hasło: ")


    conn = sqlite3.connect('mistrz_oryginał.db')
    cursor = conn.cursor()
    salt = generate_salt()
    hashed_password = hash_password(haslo_mistrza1, salt)
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                          (username TEXT PRIMARY KEY, password TEXT, salt BLOB)''')
    cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                  (username, hashed_password, sqlite3.Binary(salt)))
    conn.commit()
    conn.close()

haslo_mistrza_utworzone=input("Podaj hasło do menadżera haseł: ")
while verify_password(haslo_mistrza_utworzone) != True:
    print("Złe hasło")
    haslo_mistrza_utworzone=input("Spróbuj ponownie: ")

#-------------------------------------------------------------------- tu nie moge uzywać tej samej metody bo nie bede mógł odszyfrować hasła
co_robi = input("Chcesz stworzyć nowe konto, czy wyświetlić hasło dla już utworzonego konta? (stworzyć/wyświetlić): ")
if co_robi.upper() == "STWORZYĆ":
    nowe_konto = input("Podaj nazwę nowego konta: ")
    nowe_haslo1 = input("Podaj hasło do nowego konta: ")
    nowe_haslo2 = input("Potwierdz hasło: ")
    while nowe_haslo2 != nowe_haslo1:
        print("Hasła się nie zgadzają")
        nowe_haslo1 = input("Podaj hasło do nowego konta: ")
        nowe_haslo2 = input("Potwierdz hasło: ")
    nowe_haslo1=bytes(nowe_haslo1, "utf-8")
    sol=generate_salt2()
    klucz=PBKDF2(haslo_mistrza_utworzone, sol, dkLen=32)
    iv = generate_salt2()
    szyfr = AES.new(klucz, AES.MODE_CBC, iv)
    zaszyfrowane_dane=szyfr.encrypt(pad(nowe_haslo1, AES.block_size))
    conn_user = sqlite3.connect("konta_oryginał.db")
    cursor_user = conn_user.cursor()
    cursor_user.execute('''CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY, zaszyfrowane_dane BLOB, iv BLOB, klucz BLOB)''')
    cursor_user.execute('INSERT INTO users (login, zaszyfrowane_dane, iv, klucz) VALUES (?, ?, ?, ?)', (nowe_konto, sqlite3.Binary(zaszyfrowane_dane), sqlite3.Binary(iv), sqlite3.Binary(klucz)))
    conn_user.commit()
    conn_user.close()
    print(f"Konto {nowe_konto} zostało stworzone.")
elif co_robi.upper() == "WYŚWIETLIĆ":
    try:
        istniejace_konto=input("Podaj nazwę istniejacego konta: ")
        conn_user = sqlite3.connect("konta_oryginał.db")
        cursor_user = conn_user.cursor()
        cursor_user.execute('SELECT klucz FROM users WHERE login = ?', (istniejace_konto,))
        result = cursor_user.fetchone()[0]
        cursor_user.execute('SELECT zaszyfrowane_dane FROM users WHERE login = ?', (istniejace_konto,))
        result2=cursor_user.fetchone()[0]
        cursor_user.execute('SELECT iv FROM users WHERE login = ?', (istniejace_konto,))
        result3=cursor_user.fetchone()[0]
        szyfr = AES.new(result, AES.MODE_CBC, result3)
        zaszyfrowane_dane=szyfr.decrypt(result2)
        oryginalne_haslo = unpad(zaszyfrowane_dane, AES.block_size)
        print("Oto twoje hasło: ", str(oryginalne_haslo)[2:-1])
    except:
        print("Takie konto nie istnieje.")
