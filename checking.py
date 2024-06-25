import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import sympy
import random
from fractions import Fraction
import time
import rsa
import math


def gcd(a, b):
    """Вычисляет наибольший общий делитель (НОД) двух чисел."""
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Вычисляет обратное по модулю с использованием расширенного алгоритма Евклида."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1



# Функции для работы с непрерывными дробями и конвергентами
def continued_fraction(numerator, denominator):
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        yield quotient
        numerator, denominator = denominator, remainder

def convergents_of_cont_frac(fraction):
    convs = []
    n = []
    d = []
    for i in fraction:
        if len(n) == 0:
            n.append(i)
            d.append(1)
        elif len(n) == 1:
            n.append(i * n[0] + 1)
            d.append(i)
        else:
            n.append(i * n[-1] + n[-2])
            d.append(i * d[-1] + d[-2])
        convs.append(Fraction(n[-1], d[-1]))
    return convs

# Функция для проверки уязвимости к атаке Винера
def is_wiener_attack_vulnerable(e, n):
    print("3")
    for frac in convergents_of_cont_frac(continued_fraction(e, n)):
        k = frac.numerator
        d = frac.denominator
        if k == 0 or (e*d - 1) % k != 0:
            continue
        phi_n = (e*d - 1) // k
        s = n - phi_n + 1
        # Проверка, является ли 's' полным квадратом
        if s % 2 == 0 and (s//2)**2 - n >= 0:
            return True
    return False

global n, e, d, p, q
n, e, d, p, q = 0, 0, 0, 0, 0

# Генерация простых чисел в заданном диапазоне
def primes_range(low, high):
    sieve = [True] * (high + 1)
    for num in range(2, int(high ** 0.5) + 1):
        if sieve[num]:
            sieve[num * num:high + 1:num] = [False] * ((high - num * num) // num + 1)
    return [num for num in range(max(low, 2), high) if sieve[num]]

# Функции для генерации ключей, шифрования и расшифрования
def generate_rsa_keys():
    global n, e, d, p, q
    (public_key, private_key) = rsa.newkeys(int(len_key.get()))
    n = public_key.n
    e = public_key.e
    d = private_key.d
    print(public_key, private_key)
    return (n, e), (n, d)

# Функция для перевода сообщения в ASCII коды
def message_to_ascii(message):
    return [ord(char) for char in message]

# Функция для шифрования сообщения с использованием RSA
def encrypt_message_with_rsa(message, public_key):
    n, e = public_key
    ascii_codes = message_to_ascii(message)
    encrypted_codes = [pow(code, e, n) for code in ascii_codes]
    return encrypted_codes


def ascii_to_message(ascii_codes):
    return ''.join(chr(code) for code in ascii_codes)


# функции проверки уязвимостей
def is_fermat_vulnerable(n, max_iterations = 10000000):
    x = math.isqrt(n) + 1
    y = x * x - n
    iteration = 0

    while math.isqrt(y) ** 2 != y:
        if iteration >= max_iterations:
            return False
        x += 1
        y = x * x - n
        iteration += 1

    y_sqrt = math.isqrt(y)
    p = x + y_sqrt
    q = x - y_sqrt

    # Проверка, являются ли найденные числа делителями n
    if p * q == n:
        return True
    else:
        return False



def is_chosen_ciphertext_attack_vulnerable(n, e):
    print("2")
    for _ in range(10):
        X = random.randint(2, n - 1)
        if gcd(X, n) == 1:  # X должно быть взаимно простым с n
            X_inv = modinv(X, n)
            # Если можем найти X и X_inv, система потенциально уязвима
            return True
    return False


# Функция для обновления меток с ключами
def update_key_labels():
    global n, e, d, p, q
    public_key, private_key = generate_rsa_keys()
    n, e = public_key
    _, d = private_key
    n_label.config(text=f"n: {n}")
    e_label.config(text=f"e: {e}")
    d_label.config(text=f"d: {d}")

# Функция для шифрования сообщения и отображения нового окна с результатом
def encrypted_codes_to_hex_string(encrypted_codes):
    return ' '.join(format(code, 'x') for code in encrypted_codes)

# Функция для шифрования
def encrypt_and_show():
    global n, e, encrypted_codes
    message = message_entry.get()
    encrypted_codes = encrypt_message_with_rsa(message, (n, e))  # Сохраняем зашифрованные коды
    encrypted_hex_string = encrypted_codes_to_hex_string(encrypted_codes)
    messagebox.showinfo("Зашифрованное сообщение", encrypted_hex_string)


# Функция для проверки уязвимостей
def check_vulnerabilities():
    global n, e, p, q
    start_time = time.time()
    vulnerabilities = "Атака Ферма" + str(is_fermat_vulnerable(n)) +"Время:" +str(time.time()-start_time)+"\n"
    start_time = time.time()
    vulnerabilities += "Атака выборкой зашифрованного текста" + str(is_chosen_ciphertext_attack_vulnerable(n, e)) +"Время:" +str(time.time()-start_time)+ "\n"
    start_time = time.time()
    vulnerabilities += "Атака Винера: " + str(is_wiener_attack_vulnerable(e,n))+"Время:" +str(time.time()-start_time)
    attack_label.config(text=vulnerabilities)


# Глобальная переменная для хранения зашифрованных кодов
encrypted_codes = []

# Функция для расшифрования сообщения и отображения нового окна с результатом
def decrypt_and_show():
    global n, d
    if encrypted_codes:  # Проверяем, не пустой ли список зашифрованных кодов
        decrypted_message = ascii_to_message([pow(code, d, n) for code in encrypted_codes])
        messagebox.showinfo("Расшифрованное сообщение", decrypted_message)
    else:
        messagebox.showerror("Ошибка", "Нет зашифрованных данных для расшифровки.")



# Создание основного окна
root = tk.Tk()
root.title("RSA Шифрование")

# Создание и расположение виджетов





len_key_label = tk.Label(root, text="Введите длину ключа:")
len_key_label.pack()
len_key = tk.Entry(root)
len_key.pack()


generate_button = tk.Button(root, text="Сгенерировать ключи", command=update_key_labels)
generate_button.pack()

n_label = tk.Label(root, text="n:")
n_label.pack()

e_label = tk.Label(root, text="e:")
e_label.pack()

d_label = tk.Label(root, text="d:")
d_label.pack()

message_label = tk.Label(root, text="Введите текст для шифрования:")
message_label.pack()
message_entry = tk.Entry(root)
message_entry.pack()

encrypt_button = tk.Button(root, text="Зашифровать", command=encrypt_and_show)
encrypt_button.pack()

check_attack_button = tk.Button(root, text="Проверить уязвимости", command=check_vulnerabilities)
check_attack_button.pack()

attack_label = tk.Label(root, text="Уязвимости алгоритма:")
attack_label.pack()

decrypt_button = tk.Button(root, text="Расшифровать", command=decrypt_and_show)
decrypt_button.pack()

# Запуск главного цикла
root.mainloop()
