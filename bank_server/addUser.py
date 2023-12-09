import sqlite3

from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

import base64

name = input("Name: ")
birthYear = input("Birthyear: ")
birthMonth = input("Birthmonth: ")
birthDate = input("Birthdate: ")
adress = input("Adress: ")
password = input("Password: ")
hashedPassword = bytes(password, 'utf-8')
for i in range(10000):
    hashedPassword = SHA512.new(hashedPassword).digest()

customerID = base64.b64encode(SHA512.new(get_random_bytes(16)).digest()).decode()

connection = sqlite3.connect('database.sqlite3')
cursor = connection.cursor()
cursor.execute('''
    INSERT INTO customer (customerID, name, birthYear, birthMonth, birthDate, adress, hashPassword)
    VALUES (?, ?, ?, ?, ?, ?, ?)
''', (customerID, name, birthYear, birthMonth, birthDate, adress, hashedPassword))

connection.commit()
connection.close()