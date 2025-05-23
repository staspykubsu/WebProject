#!/usr/bin/env python3

import cgi
import pymysql
import os
import base64
import re
import html
import secrets
from http.cookies import SimpleCookie
from datetime import datetime, timedelta

CSRF_TOKEN_NAME = 'csrf_token'

def generate_csrf_token():
    return secrets.token_hex(32)

def get_csrf_token():
    cookie = SimpleCookie(os.environ.get('HTTP_COOKIE', ''))
    if CSRF_TOKEN_NAME in cookie:
        return cookie[CSRF_TOKEN_NAME].value
    return None

def set_csrf_token_cookie(token):
    expires = (datetime.now() + timedelta(hours=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    print(f"Set-Cookie: {CSRF_TOKEN_NAME}={token}; Expires={expires}; Path=/; HttpOnly; SameSite=Strict")

def validate_csrf_token(form_token):
    cookie_token = get_csrf_token()
    if not cookie_token or not form_token:
        return False
    return secrets.compare_digest(cookie_token, form_token)

def create_connection():
    try:
        return pymysql.connect(
            host='84.201.171.207',
            user='u68593',
            password='9258357',
            database='web_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("Ошибка подключения к базе данных")
        return None

def check_admin_auth():
    auth = os.environ.get('HTTP_AUTHORIZATION')
    if not auth:
        return False
    
    auth_type, auth_string = auth.split(' ', 1)
    if auth_type.lower() != 'basic':
        return False
    
    try:
        decoded = base64.b64decode(auth_string).decode('utf-8')
        username, password = decoded.split(':', 1)
    except:
        return False
    
    connection = create_connection()
    if not connection:
        return False
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT password_hash FROM admin_credentials 
                WHERE username = %s
            """, (username,))
            result = cursor.fetchone()
            if result:
                return True
    except pymysql.Error:
        return False
    finally:
        connection.close()
    
    return False

def validate_form_data(data):
    errors = {}
    patterns = {
        'last_name': r'^[А-Яа-яЁё]+$',
        'first_name': r'^[А-Яа-яЁё]+$',
        'patronymic': r'^[А-Яа-яЁё]*$',
        'phone': r'^\+?\d{10,15}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'bio': r'^.{10,}$'
    }
    messages = {
        'last_name': "Фамилия должна содержать только буквы кириллицы.",
        'first_name': "Имя должно содержать только буквы кириллицы.",
        'patronymic': "Отчество должно содержать только буквы кириллицы (если указано).",
        'phone': "Телефон должен быть длиной от 10 до 15 цифр и может начинаться с '+'",
        'email': "Некорректный email. Пример: example@domain.com",
        'bio': "Биография должна содержать не менее 10 символов."
    }

    for field, pattern in patterns.items():
        if field in data and not re.match(pattern, data[field]):
            errors[field] = messages[field]

    if 'gender' not in data or data['gender'] not in ['male', 'female']:
        errors['gender'] = "Выберите пол."

    if 'languages[]' not in data or not data['languages[]']:
        errors['languages'] = "Выберите хотя бы один язык программирования."

    if 'contract' not in data or not data['contract']:
        errors['contract'] = "Необходимо подтвердить ознакомление с контрактом."

    return errors

def escape_html(text):
    return html.escape(str(text))

def generate_admin_page():
    csrf_token = get_csrf_token()
    if not csrf_token:
        csrf_token = generate_csrf_token()
        set_csrf_token_cookie(csrf_token)
    
    connection = create_connection()
    if not connection:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка подключения к базе данных</h1>")
        return
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT a.id, a.last_name, a.first_name, a.patronymic, 
                       a.phone, a.email, a.birthdate, a.gender, a.bio, a.contract,
                       GROUP_CONCAT(pl.name) as languages
                FROM applications a
                LEFT JOIN application_languages al ON a.id = al.application_id
                LEFT JOIN programming_languages pl ON al.language_id = pl.id
                GROUP BY a.id
                ORDER BY a.id
            """)
            applications = cursor.fetchall()
            
            cursor.execute("""
                SELECT pl.name as language, COUNT(al.application_id) as count
                FROM programming_languages pl
                LEFT JOIN application_languages al ON pl.id = al.language_id
                GROUP BY pl.name
                ORDER BY count DESC
            """)
            language_stats = cursor.fetchall()
            
        html = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Административная панель</title>
             <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                h1, h2 {{
                    color: #333;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                    table-layout: fixed;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                    word-wrap: break-word;
                }}
                th {{
                    background-color: #f2f2f2;
                    position: sticky;
                    top: 0;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                tr:hover {{
                    background-color: #f1f1f1;
                }}
                .stats {{
                    margin-top: 30px;
                    padding: 15px;
                    background-color: #f0f8ff;
                    border-radius: 5px;
                }}
                .action-buttons form {{
                    display: inline-block;
                    margin-right: 5px;
                }}
                button {{
                    padding: 5px 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                button:hover {{
                    background-color: #45a049;
                }}
                button[type="submit"] {{
                    background-color: #f44336;
                }}
                button[type="submit"]:hover {{
                    background-color: #d32f2f;
                }}
                .container {{
                    max-width: 100%;
                    overflow-x: auto;
                }}
            </style>
        </head>
        <body>
            <h1>Административная панель</h1>
            
            <h2>Все заявки</h2>
            <div class="container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 5%;">ID</th>
                            <th style="width: 8%;">Фамилия</th>
                            <th style="width: 8%;">Имя</th>
                            <th style="width: 8%;">Отчество</th>
                            <th style="width: 10%;">Телефон</th>
                            <th style="width: 10%;">Email</th>
                            <th style="width: 8%;">Дата рождения</th>
                            <th style="width: 5%;">Пол</th>
                            <th style="width: 10%;">Языки</th>
                            <th style="width: 15%;">Биография</th>
                            <th style="width: 5%;">Контракт</th>
                            <th style="width: 8%;">Действия</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for app in applications:
            languages = app['languages'].split(',') if app['languages'] else []
            html += f"""
                    <tr>
                        <td>{escape_html(app['id'])}</td>
                        <td>{escape_html(app['last_name'])}</td>
                        <td>{escape_html(app['first_name'])}</td>
                        <td>{escape_html(app['patronymic'] or '-')}</td>
                        <td>{escape_html(app['phone'])}</td>
                        <td>{escape_html(app['email'])}</td>
                        <td>{escape_html(app['birthdate'])}</td>
                        <td>{'М' if app['gender'] == 'male' else 'Ж'}</td>
                        <td>{escape_html(', '.join(languages))}</td>
                        <td>{escape_html(app['bio'][:50])}{'...' if len(app['bio']) > 50 else ''}</td>
                        <td>{'Да' if app['contract'] else 'Нет'}</td>
                        <td class="action-buttons">
                            <form action="admin.py" method="post">
                                <input type="hidden" name="id" value="{escape_html(app['id'])}">
                                <input type="hidden" name="action" value="edit">
                                <input type="hidden" name="csrf_token" value="{csrf_token}">
                                <button type="submit">Редактировать</button>
                            </form>
                            <form action="admin.py" method="post" onsubmit="return confirm('Удалить эту запись?');">
                                <input type="hidden" name="id" value="{escape_html(app['id'])}">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="csrf_token" value="{csrf_token}">
                                <button type="submit">Удалить</button>
                            </form>
                        </td>
                    </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
            
            <div class="stats">
                <h2>Статистика по языкам программирования</h2>
                <div class="container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 70%;">Язык программирования</th>
                                <th style="width: 30%;">Количество пользователей</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for stat in language_stats:
            html += f"""
                        <tr>
                            <td>{escape_html(stat['language'])}</td>
                            <td>{escape_html(stat['count'])}</td>
                        </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
        
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(html)
        
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка базы данных</h1>")
    finally:
        connection.close()

def generate_edit_form(application_id, errors=None, form_data=None):
    if not isinstance(application_id, int) or application_id <= 0:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Неверный ID заявки</h1>")
        return

    # Получаем или генерируем CSRF токен
    csrf_token = get_csrf_token()
    if not csrf_token:
        csrf_token = generate_csrf_token()
        set_csrf_token_cookie(csrf_token)

    connection = create_connection()
    if not connection:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка подключения к базе данных</h1>")
        return
    
    try:
        with connection.cursor() as cursor:
            if not form_data:
                cursor.execute("""
                    SELECT a.*, GROUP_CONCAT(pl.name) as languages
                    FROM applications a
                    LEFT JOIN application_languages al ON a.id = al.application_id
                    LEFT JOIN programming_languages pl ON al.language_id = pl.id
                    WHERE a.id = %s
                    GROUP BY a.id
                """, (application_id,))
                application = cursor.fetchone()
                
                if not application:
                    print("Content-Type: text/html; charset=utf-8")
                    print("\n")
                    print("<h1>Заявка не найдена</h1>")
                    return
                
                form_data = {
                    'last_name': application['last_name'],
                    'first_name': application['first_name'],
                    'patronymic': application['patronymic'] or '',
                    'phone': application['phone'],
                    'email': application['email'],
                    'birthdate': application['birthdate'],
                    'gender': application['gender'],
                    'bio': application['bio'],
                    'contract': application['contract'],
                    'languages[]': application['languages'].split(',') if application['languages'] else []
                }
            
            cursor.execute("SELECT id, name FROM programming_languages")
            all_languages = cursor.fetchall()
            
            error_classes = {
                'last_name': 'error' if errors and 'last_name' in errors else '',
                'first_name': 'error' if errors and 'first_name' in errors else '',
                'patronymic': 'error' if errors and 'patronymic' in errors else '',
                'phone': 'error' if errors and 'phone' in errors else '',
                'email': 'error' if errors and 'email' in errors else '',
                'bio': 'error' if errors and 'bio' in errors else '',
                'gender': 'error' if errors and 'gender' in errors else '',
                'languages': 'error' if errors and 'languages' in errors else '',
                'contract': 'error' if errors and 'contract' in errors else ''
            }
            
            error_messages = {
                'last_name': escape_html(errors.get('last_name', '')) if errors else '',
                'first_name': escape_html(errors.get('first_name', '')) if errors else '',
                'patronymic': escape_html(errors.get('patronymic', '')) if errors else '',
                'phone': escape_html(errors.get('phone', '')) if errors else '',
                'email': escape_html(errors.get('email', '')) if errors else '',
                'bio': escape_html(errors.get('bio', '')) if errors else '',
                'gender': escape_html(errors.get('gender', '')) if errors else '',
                'languages': escape_html(errors.get('languages', '')) if errors else '',
                'contract': escape_html(errors.get('contract', '')) if errors else ''
            }
            
            html = f"""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Редактирование заявки</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 20px;
                        background-color: #f5f5f5;
                    }}
                    .form-container {{
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: white;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }}
                    h1 {{
                        color: #333;
                        margin-top: 0;
                    }}
                    label {{
                        display: block;
                        margin-top: 10px;
                        font-weight: bold;
                    }}
                    input[type="text"],
                    input[type="tel"],
                    input[type="email"],
                    input[type="date"],
                    textarea,
                    select {{
                        width: 100%;
                        padding: 8px;
                        margin-top: 5px;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                        box-sizing: border-box;
                    }}
                    textarea {{
                        height: 100px;
                        resize: vertical;
                    }}
                    .radio-group {{
                        margin: 10px 0;
                    }}
                    .radio-group label {{
                        display: inline;
                        font-weight: normal;
                        margin-right: 15px;
                    }}
                    .language-checkboxes {{
                        display: flex;
                        flex-wrap: wrap;
                        gap: 10px;
                        margin: 10px 0;
                    }}
                    .language-checkbox {{
                        display: flex;
                        align-items: center;
                        white-space: nowrap;
                    }}
                    .buttons {{
                        margin-top: 20px;
                        display: flex;
                        gap: 10px;
                    }}
                    button {{
                        padding: 8px 15px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }}
                    button:hover {{
                        background-color: #45a049;
                    }}
                    a.button {{
                        display: inline-block;
                        padding: 8px 15px;
                        background-color: #f44336;
                        color: white;
                        text-decoration: none;
                        border-radius: 4px;
                        text-align: center;
                    }}
                    a.button:hover {{
                        background-color: #d32f2f;
                    }}
                    .error-message {{
                        color: #f44336;
                        font-size: 0.9em;
                        margin-top: 5px;
                        display: block;
                    }}
                    .error {{
                        border-color: #f44336 !important;
                    }}
                </style>
            </head>
            <body>
                <div class="form-container">
                    <h1>Редактирование заявки #{escape_html(application_id)}</h1>
                    
                    <form action="admin.py" method="post">
                        <input type="hidden" name="id" value="{escape_html(application_id)}">
                        <input type="hidden" name="action" value="update">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        
                        <label for="last_name">Фамилия:</label>
                        <input type="text" id="last_name" name="last_name" value="{escape_html(form_data['last_name'])}" 
                               class="{error_classes['last_name']}" required>
                        <span class="error-message">{error_messages['last_name']}</span>
                        
                        <label for="first_name">Имя:</label>
                        <input type="text" id="first_name" name="first_name" value="{escape_html(form_data['first_name'])}" 
                               class="{error_classes['first_name']}" required>
                        <span class="error-message">{error_messages['first_name']}</span>
                        
                        <label for="patronymic">Отчество:</label>
                        <input type="text" id="patronymic" name="patronymic" value="{escape_html(form_data['patronymic'])}"
                               class="{error_classes['patronymic']}">
                        <span class="error-message">{error_messages['patronymic']}</span>
                        
                        <label for="phone">Телефон:</label>
                        <input type="tel" id="phone" name="phone" value="{escape_html(form_data['phone'])}" 
                               class="{error_classes['phone']}" required>
                        <span class="error-message">{error_messages['phone']}</span>
                        
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" value="{escape_html(form_data['email'])}" 
                               class="{error_classes['email']}" required>
                        <span class="error-message">{error_messages['email']}</span>
                        
                        <label for="birthdate">Дата рождения:</label>
                        <input type="date" id="birthdate" name="birthdate" value="{escape_html(form_data['birthdate'])}" required>
                        
                        <label>Пол:</label>
                        <div class="radio-group {'error' if error_classes['gender'] else ''}">
                            <input type="radio" id="male" name="gender" value="male" 
                                   {'checked' if form_data['gender'] == 'male' else ''} required>
                            <label for="male">Мужской</label>
                            
                            <input type="radio" id="female" name="gender" value="female" 
                                   {'checked' if form_data['gender'] == 'female' else ''} required>
                            <label for="female">Женский</label>
                        </div>
                        <span class="error-message">{error_messages['gender']}</span>
                        
                        <label>Любимые языки программирования:</label>
                        <div class="language-checkboxes {'error' if error_classes['languages'] else ''}">
            """
            
            for lang in all_languages:
                checked = 'checked' if lang['name'] in form_data['languages[]'] else ''
                html += f"""
                            <div class="language-checkbox">
                                <input type="checkbox" id="lang_{escape_html(lang['id'])}" name="languages[]" value="{escape_html(lang['name'])}" {checked}>
                                <label for="lang_{escape_html(lang['id'])}">{escape_html(lang['name'])}</label>
                            </div>
                """
            
            html += f"""
                        </div>
                        <span class="error-message">{error_messages['languages']}</span>
                        
                        <label for="bio">Биография:</label>
                        <textarea id="bio" name="bio" class="{error_classes['bio']}" required>{escape_html(form_data['bio'])}</textarea>
                        <span class="error-message">{error_messages['bio']}</span>
                        
                        <div class="{'error' if error_classes['contract'] else ''}">
                            <input type="checkbox" id="contract" name="contract" {'checked' if form_data['contract'] else ''} required>
                            <label for="contract">С контрактом ознакомлен(а)</label>
                        </div>
                        <span class="error-message">{error_messages['contract']}</span>
                        
                        <div class="buttons">
                            <button type="submit">Сохранить</button>
                            <a href="admin.py" class="button">Отмена</a>
                        </div>
                    </form>
                </div>
            </body>
            </html>
            """
            
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print(html)
            
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка базы данных</h1>")
    finally:
        connection.close()

def update_application(application_id, form_data):
    if not isinstance(application_id, int) or application_id <= 0:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Неверный ID заявки</h1>")
        return False

    errors = validate_form_data(form_data)
    if errors:
        generate_edit_form(application_id, errors, form_data)
        return False
    
    connection = create_connection()
    if not connection:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка подключения к базе данных</h1>")
        return False
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE applications 
                SET last_name = %s, first_name = %s, patronymic = %s, 
                    phone = %s, email = %s, birthdate = %s, 
                    gender = %s, bio = %s, contract = %s
                WHERE id = %s
            """, (
                form_data['last_name'],
                form_data['first_name'],
                form_data['patronymic'],
                form_data['phone'],
                form_data['email'],
                form_data['birthdate'],
                form_data['gender'],
                form_data['bio'],
                form_data['contract'],
                application_id
            ))
            
            cursor.execute("DELETE FROM application_languages WHERE application_id = %s", (application_id,))
            
            if 'languages[]' in form_data:
                selected_languages = form_data['languages[]']
                if not isinstance(selected_languages, list):
                    selected_languages = [selected_languages]
                
                for lang_name in selected_languages:
                    cursor.execute("SELECT id FROM programming_languages WHERE name = %s", (lang_name,))
                    lang_id = cursor.fetchone()
                    if lang_id:
                        cursor.execute("""
                            INSERT INTO application_languages (application_id, language_id)
                            VALUES (%s, %s)
                        """, (application_id, lang_id['id']))
            
            connection.commit()
            print("Status: 303 See Other")
            print("Location: admin.py")
            print("\n")
            return True
            
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка базы данных</h1>")
        connection.rollback()
        return False
    finally:
        connection.close()

def delete_application(application_id):
    if not isinstance(application_id, int) or application_id <= 0:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Неверный ID заявки</h1>")
        return False

    connection = create_connection()
    if not connection:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка подключения к базе данных</h1>")
        return False
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM application_languages WHERE application_id = %s", (application_id,))
            cursor.execute("DELETE FROM applications WHERE id = %s", (application_id,))
            
            connection.commit()
            print("Status: 303 See Other")
            print("Location: admin.py")
            print("\n")
            return True
            
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Ошибка базы данных</h1>")
        connection.rollback()
        return False
    finally:
        connection.close()

if __name__ == "__main__":
    if not check_admin_auth():
        print("Status: 401 Unauthorized")
        print("WWW-Authenticate: Basic realm=\"Admin Area\"")
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>401 Не авторизован</h1>")
        print("<p>Требуется авторизация для доступа к этой странице.</p>")
        exit()
    
    form = cgi.FieldStorage()
    action = form.getvalue('action')
    
    # CSRF protection for POST requests
    if os.environ.get('REQUEST_METHOD') == 'POST':
        csrf_token = form.getvalue('csrf_token')
        if not validate_csrf_token(csrf_token):
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print("<h1>Ошибка CSRF токена</h1>")
            print("<p>Недействительный токен безопасности. Пожалуйста, обновите страницу и попробуйте снова.</p>")
            exit()
    
    # Обработка GET-запросов (показ страницы)
    if os.environ.get('REQUEST_METHOD') == 'GET' and not action:
        generate_admin_page()
        exit()
    
    # Обработка POST-запросов
    if action == 'edit':
        application_id = form.getvalue('id')
        if application_id and application_id.isdigit():
            generate_edit_form(int(application_id))
        else:
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print("<h1>Неверный ID заявки</h1>")
    
    elif action == 'update':
        application_id = form.getvalue('id')
        if application_id and application_id.isdigit():
            form_data = {
                'last_name': form.getvalue('last_name', '').strip(),
                'first_name': form.getvalue('first_name', '').strip(),
                'patronymic': form.getvalue('patronymic', '').strip(),
                'phone': form.getvalue('phone', '').strip(),
                'email': form.getvalue('email', '').strip(),
                'birthdate': form.getvalue('birthdate', '').strip(),
                'gender': form.getvalue('gender', '').strip(),
                'bio': form.getvalue('bio', '').strip(),
                'contract': 1 if form.getvalue('contract') else 0,
                'languages[]': form.getlist('languages[]')
            }
            
            update_application(int(application_id), form_data)
        else:
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print("<h1>Неверный ID заявки</h1>")
    
    elif action == 'delete':
        application_id = form.getvalue('id')
        if application_id and application_id.isdigit():
            delete_application(int(application_id))
        else:
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print("<h1>Неверный ID заявки</h1>")
    
    else:
        generate_admin_page()