#!/usr/bin/env python3

import pymysql
import hashlib
import getpass

def create_connection():
    try:
        return pymysql.connect(
            host='51.250.39.94',
            user='u68593',
            password='9258357',
            database='web_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        print(f"Ошибка подключения к базе данных: {e}")
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_admin_account():
    username = input("Введите имя пользователя администратора: ")
    password = getpass.getpass("Введите пароль администратора: ")
    password_confirm = getpass.getpass("Подтвердите пароль администратора: ")
    
    if password != password_confirm:
        print("Пароли не совпадают!")
        return
    
    connection = create_connection()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW TABLES LIKE 'admin_credentials'")
            result = cursor.fetchone()
            
            if not result:
                cursor.execute("""
                    CREATE TABLE admin_credentials (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(64) NOT NULL UNIQUE,
                        password_hash VARCHAR(128) NOT NULL
                    )
                """)
                print("Таблица admin_credentials создана")
            
            cursor.execute("SELECT id FROM admin_credentials WHERE username = %s", (username,))
            existing_admin = cursor.fetchone()
            
            if existing_admin:
                cursor.execute("""
                    UPDATE admin_credentials 
                    SET password_hash = %s 
                    WHERE username = %s
                """, (hash_password(password), username))
                print("Учетные данные администратора обновлены")
            else:
                cursor.execute("""
                    INSERT INTO admin_credentials (username, password_hash)
                    VALUES (%s, %s)
                """, (username, hash_password(password)))
                print("Учетные данные администратора созданы")
            
            connection.commit()
            
    except pymysql.Error as e:
        print(f"Ошибка базы данных: {e}")
        connection.rollback()
    finally:
        connection.close()

if __name__ == "__main__":
    print("Инициализация учетной записи администратора")
    init_admin_account()