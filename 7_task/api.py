#!/usr/bin/env python3
import cgi
import json
import pymysql
import os
import secrets
import hashlib
import re
from http.cookies import SimpleCookie
from datetime import datetime, timedelta
import sys
import base64

def create_connection():
    try:
        return pymysql.connect(
            host='158.160.171.1',
            user='u68593',
            password='9258357',
            database='web_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        return None

def validate_form_data(data):
    errors = {}
    patterns = {
        'last_name': r'^[А-Яа-яЁё]+$',
        'first_name': r'^[А-Яа-яЁё]+$',
        'patronymic': r'^[А-Яа-яЁё]*$',
        'phone': r'^\+?\d{10,15}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'birthdate': r'^\d{4}-\d{2}-\d{2}$',
        'bio': r'^.{10,}$'
    }
    messages = {
        'last_name': "Фамилия должна содержать только буквы кириллицы.",
        'first_name': "Имя должно содержать только буквы кириллицы.",
        'patronymic': "Отчество должно содержать только буквы кириллицы (если указано).",
        'phone': "Телефон должен быть длиной от 10 до 15 цифр и может начинаться с '+'",
        'email': "Некорректный email. Пример: example@domain.com",
        'birthdate': "Дата рождения должна быть в формате YYYY-MM-DD.",
        'bio': "Биография должна содержать не менее 10 символов."
    }
    for field, pattern in patterns.items():
        if field in data and not re.match(pattern, data[field]):
            errors[field] = messages[field]
    if 'gender' not in data or data['gender'] not in ['male', 'female']:
        errors['gender'] = "Выберите пол."
    if 'languages' not in data or not data['languages']:
        errors['languages'] = "Выберите хотя бы один язык программирования."
    if 'contract' not in data or not data['contract']:
        errors['contract'] = "Необходимо подтвердить ознакомление с контрактом."
    return errors

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_credentials():
    username = secrets.token_hex(8)
    password = secrets.token_hex(8)
    return {'username': username, 'password': password}

def create_user(connection, data):
    cursor = connection.cursor()
    try:
        credentials = generate_credentials()
        hashed_password = hash_password(credentials['password'])
        cursor.execute("""
            INSERT INTO applications 
            (last_name, first_name, patronymic, phone, email, birthdate, 
             gender, bio, contract, username, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['last_name'], data['first_name'], data['patronymic'],
            data['phone'], data['email'], data['birthdate'],
            data['gender'], data['bio'], data['contract'],
            credentials['username'], hashed_password
        ))
        application_id = cursor.lastrowid
        if not application_id:
            raise Exception("Не удалось получить ID заявки")
        cursor.execute("DELETE FROM application_languages WHERE application_id=%s", (application_id,))
        language_ids = {
            'Pascal': 1, 'C': 2, 'C++': 3, 'JavaScript': 4, 'PHP': 5,
            'Python': 6, 'Java': 7, 'Haskel': 8, 'Clojure': 9,
            'Prolog': 10, 'Scala': 11, 'Go': 12
        }
        for language in data['languages']:
            language_id = language_ids.get(language)
            if language_id:
                cursor.execute("""
                    INSERT INTO application_languages (application_id, language_id)
                    VALUES (%s, %s)
                """, (application_id, language_id))
        connection.commit()
        return {
            'status': 'success',
            'credentials': credentials,
            'profile_url': f"/profile/{application_id}"
        }
    except Exception as e:
        connection.rollback()
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        cursor.close()

def update_user(connection, username, password, data):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT id, password_hash FROM applications WHERE username=%s
        """, (username,))
        result = cursor.fetchone()
        if not result:
            return {'status': 'error', 'message': 'Пользователь не найден'}
        if result['password_hash'] != hash_password(password):
            return {'status': 'error', 'message': 'Неверный пароль'}
        application_id = result['id']
        cursor.execute("""
            UPDATE applications 
            SET last_name=%s, first_name=%s, patronymic=%s, phone=%s, email=%s, 
                birthdate=%s, gender=%s, bio=%s, contract=%s
            WHERE username=%s
        """, (
            data['last_name'], data['first_name'], data['patronymic'],
            data['phone'], data['email'], data['birthdate'],
            data['gender'], data['bio'], data['contract'],
            username
        ))
        cursor.execute("DELETE FROM application_languages WHERE application_id=%s", (application_id,))
        language_ids = {
            'Pascal': 1, 'C': 2, 'C++': 3, 'JavaScript': 4, 'PHP': 5,
            'Python': 6, 'Java': 7, 'Haskel': 8, 'Clojure': 9,
            'Prolog': 10, 'Scala': 11, 'Go': 12
        }
        for language in data['languages']:
            language_id = language_ids.get(language)
            if language_id:
                cursor.execute("""
                    INSERT INTO application_languages (application_id, language_id)
                    VALUES (%s, %s)
                """, (application_id, language_id))
        connection.commit()
        return {
            'status': 'success',
            'message': 'Данные успешно обновлены'
        }
    except Exception as e:
        connection.rollback()
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        cursor.close()

def get_user_data(connection, username, password):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT a.*, GROUP_CONCAT(pl.name) as languages
            FROM applications a
            LEFT JOIN application_languages al ON a.id = al.application_id
            LEFT JOIN programming_languages pl ON al.language_id = pl.id
            WHERE a.username=%s
            GROUP BY a.id
        """, (username,))
        result = cursor.fetchone()
        if not result:
            return {'status': 'error', 'message': 'Пользователь не найден'}
        if result['password_hash'] != hash_password(password):
            return {'status': 'error', 'message': 'Неверный пароль'}
        data = {
            'status': 'success',
            'data': {
                'last_name': result['last_name'],
                'first_name': result['first_name'],
                'patronymic': result['patronymic'],
                'phone': result['phone'],
                'email': result['email'],
                'birthdate': result['birthdate'],
                'gender': result['gender'],
                'languages': result['languages'].split(',') if result['languages'] else [],
                'bio': result['bio'],
                'contract': result['contract']
            }
        }
        return data
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        cursor.close()

def handle_request():
    method = os.environ.get('REQUEST_METHOD', 'GET')
    content_type = os.environ.get('CONTENT_TYPE', '')

    data = {}
    if method in ['POST', 'PUT']:
        if 'application/json' in content_type:
            try:
                input_data = json.loads(sys.stdin.read())
                data.update(input_data)
            except:
                pass
        elif 'application/xml' in content_type:
            try:
                xml_data = sys.stdin.read()
                data = parse_simple_xml(xml_data)
            except:
                pass
        elif 'application/x-www-form-urlencoded' in content_type:
            form = cgi.FieldStorage()
            for key in form.keys():
                if key == 'languages':
                    data[key] = form.getlist(key)
                else:
                    data[key] = form.getvalue(key)

    auth = os.environ.get('HTTP_AUTHORIZATION', '')
    username = password = ''
    if auth.startswith('Basic '):
        try:
            auth_decoded = base64.b64decode(auth[6:]).decode('utf-8')
            username, password = auth_decoded.split(':', 1)
        except:
            pass

    path_info = os.environ.get('PATH_INFO', '')
    connection = create_connection()
    if not connection:
        return {
            'status': 'error',
            'message': 'Database connection error',
            'code': 500
        }

    try:
        if method == 'POST' and path_info == '/register':
            errors = validate_form_data(data)
            if errors:
                return {
                    'status': 'error',
                    'errors': errors,
                    'code': 400
                }
            result = create_user(connection, data)
            result['code'] = 201 if result['status'] == 'success' else 400
            return result
        elif method == 'PUT' and path_info.startswith('/profile/'):
            if not username or not password:
                return {
                    'status': 'error',
                    'message': 'Authentication required',
                    'code': 401
                }
            errors = validate_form_data(data)
            if errors:
                return {
                    'status': 'error',
                    'errors': errors,
                    'code': 400
                }
            result = update_user(connection, username, password, data)
            result['code'] = 200 if result['status'] == 'success' else 400
            return result
        elif method == 'GET' and path_info.startswith('/profile/'):
            if not username or not password:
                return {
                    'status': 'error',
                    'message': 'Authentication required',
                    'code': 401
                }
            result = get_user_data(connection, username, password)
            result['code'] = 200 if result['status'] == 'success' else 400
            return result
        else:
            return {
                'status': 'error',
                'message': 'Invalid request',
                'code': 404
            }
    finally:
        connection.close()

def parse_simple_xml(xml_string):
    data = {}
    for tag in ['last_name', 'first_name', 'patronymic', 'phone', 'email', 
                'birthdate', 'gender', 'bio', 'contract']:
        start_tag = f'<{tag}>'
        end_tag = f'</{tag}>'
        if start_tag in xml_string and end_tag in xml_string:
            start = xml_string.index(start_tag) + len(start_tag)
            end = xml_string.index(end_tag)
            data[tag] = xml_string[start:end].strip()
    languages = []
    lang_tag = '<language>'
    while lang_tag in xml_string:
        start = xml_string.index(lang_tag) + len(lang_tag)
        end = xml_string.index('</language>', start)
        languages.append(xml_string[start:end].strip())
        xml_string = xml_string[end + len('</language>'):]
    if languages:
        data['languages'] = languages
    return data

if __name__ == "__main__":
    response = handle_request()
    accept = os.environ.get('HTTP_ACCEPT', 'application/json')
    if 'application/xml' in accept:
        content_type = 'application/xml'
        xml_response = '<response>'
        for key, value in response.items():
            if isinstance(value, dict):
                xml_response += f'<{key}>'
                for k, v in value.items():
                    xml_response += f'<{k}>{v}</{k}>'
                xml_response += f'</{key}>'
            elif isinstance(value, list):
                xml_response += f'<{key}>'
                for item in value:
                    xml_response += f'<item>{item}</item>'
                xml_response += f'</{key}>'
            else:
                xml_response += f'<{key}>{value}</{key}>'
        xml_response += '</response>'
        output = xml_response
    else:
        content_type = 'application/json'
        output = json.dumps(response, ensure_ascii=False)
    status_code = response.get('code', 200)
    status_text = {
        200: 'OK',
        201: 'Created',
        400: 'Bad Request',
        401: 'Unauthorized',
        404: 'Not Found',
        500: 'Internal Server Error'
    }.get(status_code, 'OK')
    print(f"Status: {status_code} {status_text}")
    print(f"Content-Type: {content_type}; charset=utf-8")
    print()
    print(output)
