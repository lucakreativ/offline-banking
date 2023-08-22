import sqlite3
import time

#challenge for getting amount
def getBalance(accountID):
    pass

def addTransaction(TransactionType, AccountTypeSender, AccountSender, AccountTypeReciever, AccountReciever, amount, UnixTimeTransaction, UnixTimeRecieved):
    pass

def changeAccountBalance(Account, amount):
    pass

def transferMoney(accountSender, accountReciever, amount, UinxTimeTransaction):
    addTransaction(0, 0, accountSender, 0, accountReciever, amount, UinxTimeTransaction, time.time())
    changeAccountBalance(accountSender, -amount)
    changeAccountBalance(accountReciever, amount)


def depositMoney(accountSender, accountReciever, amount, UnixTimeTransaction):
    addTransaction(1, 1, accountSender, 0, accountReciever, amount, UnixTimeTransaction, time.time())
    changeAccountBalance(accountReciever, amount)