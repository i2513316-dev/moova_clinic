import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="mysql-proyecto-moova.alwaysdata.net",
        user="proyecto-moova",
        password="Moova1234",
        database="proyecto-moova_01",
        port=3306
    )
