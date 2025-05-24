#!/usr/bin/env python3
import cgi
import http.cookies
import re
import pymysql
from datetime import datetime, timedelta
import os
import secrets
import hashlib
import html
import json

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
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(f"Ошибка подключения к базе данных.")
        return None

def validate_form(data):
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

def escape_html(text):
    return html.escape(str(text), quote=True)

def generate_html_form(data, errors, is_logged_in=False, credentials=None):
    login_section = ""
    if not is_logged_in:
        login_section = """
        <div class="login-section">
            <h2>Вход</h2>
            <form id="loginForm" action="submit_form.py" method="POST">
                <input type="hidden" name="action" value="login">
                <label for="username">Логин:</label>
                <input type="text" id="username" name="username" required>
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Войти</button>
            </form>
        </div>
        """

    credentials_section = ""
    if credentials:
        credentials_section = f"""
        <div class="credentials">
            <h3>Ваши учетные данные (сохраните их):</h3>
            <p><strong>Логин:</strong> {escape_html(credentials['username'])}</p>
            <p><strong>Пароль:</strong> {escape_html(credentials['password'])}</p>
        </div>
        """

    logout_button = ""
    if is_logged_in:
        logout_button = """
        <form id="logoutForm" action="submit_form.py" method="POST">
            <input type="hidden" name="action" value="logout">
            <button type="submit" class="logout-button">Выйти</button>
        </form>
        """
    csrf_token_value = escape_html(generate_csrf_token())

    # Подготовка данных для JavaScript
    errors_js = json.dumps({k: v for k, v in errors.items() if v}, ensure_ascii=False)

    script = f"""
    document.addEventListener('DOMContentLoaded', function() {{
        const form = document.getElementById('mainForm');
        if (!form) return;
        
        // Показываем начальные ошибки
        const initialErrors = {errors_js};
        Object.keys(initialErrors).forEach(field => {{
            const errorElement = document.querySelector(`span.${{field}}_error`);
            if (errorElement) {{
                errorElement.textContent = initialErrors[field];
            }}
            const inputElement = document.querySelector(`[name="${{field}}"]`) || 
                               document.querySelector(`[name="${{field}}[]"]`);
            if (inputElement) {{
                inputElement.classList.add('error');
            }}
        }});

        form.addEventListener('submit', function(e) {{
            e.preventDefault();
            const formData = {{
                last_name: form.last_name.value,
                first_name: form.first_name.value,
                patronymic: form.patronymic.value,
                phone: form.phone.value,
                email: form.email.value,
                birthdate: form.birthdate.value,
                gender: form.querySelector('input[name="gender"]:checked')?.value,
                languages: Array.from(form.querySelectorAll('select[name="languages[]"] option:checked')).map(o => o.value),
                bio: form.bio.value,
                contract: form.contract.checked
            }};
            
            // Валидация
            const errors = validateForm(formData);
            displayErrors(errors);
            
            if (Object.keys(errors).length === 0) {{
                const isLoggedIn = {str(is_logged_in).lower()};
                const url = isLoggedIn ? '/api/profile/' + window.location.pathname.split('/').pop() : '/api/register';
                const method = isLoggedIn ? 'PUT' : 'POST';
                sendFormData(url, method, formData, isLoggedIn);
            }}
        }});

        function validateForm(data) {{
            const errors = {{}};
            const patterns = {{
                'last_name': /^[А-Яа-яЁё]+$/,
                'first_name': /^[А-Яа-яЁё]+$/,
                'patronymic': /^[А-Яа-яЁё]*$/,
                'phone': /^\\+?\\d{{10,15}}$/,
                'email': /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$/,
                'birthdate': /^\\d{{4}}-\\d{{2}}-\\d{{2}}$/,
                'bio': /^.{{10,}}$/
            }};
            const messages = {{
                'last_name': "Фамилия должна содержать только буквы кириллицы.",
                'first_name': "Имя должно содержать только буквы кириллицы.",
                'patronymic': "Отчество должно содержать только буквы кириллицы (если указано).",
                'phone': "Телефон должен быть длиной от 10 до 15 цифр и может начинаться с '+'",
                'email': "Некорректный email. Пример: example@domain.com",
                'birthdate': "Дата рождения должна быть в формате YYYY-MM-DD.",
                'bio': "Биография должна содержать не менее 10 символов.",
                'gender': "Выберите пол.",
                'languages': "Выберите хотя бы один язык программирования.",
                'contract': "Необходимо подтвердить ознакомление с контрактом."
            }};

            for (const field in patterns) {{
                if (data[field] && !patterns[field].test(data[field])) {{
                    errors[field] = messages[field];
                }}
            }}
            if (!data.gender) errors.gender = messages.gender;
            if (!data.languages || data.languages.length === 0) errors.languages = messages.languages;
            if (!data.contract) errors.contract = messages.contract;
            return errors;
        }}

        function displayErrors(errors) {{
            // Сначала очищаем все ошибки
            document.querySelectorAll('.error-message').forEach(el => el.textContent = '');
            document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
            
            // Затем добавляем новые
            for (const field in errors) {{
                const errorElement = document.querySelector(`span.${{field}}_error`);
                let inputElement = document.querySelector(`[name="${{field}}"]`);
                
                if (!inputElement) {{
                    // Для radio и checkbox
                    inputElement = document.querySelector(`input[name="${{field}}"]`);
                }}
                
                if (!inputElement && field === 'languages') {{
                    inputElement = document.querySelector('select[name="languages[]"]');
                }}
                
                if (errorElement) {{
                    errorElement.textContent = errors[field];
                }}
                if (inputElement) {{
                    inputElement.classList.add('error');
                }}
            }}
        }}
        
        function sendFormData(url, method, data, isLoggedIn) {{
            const headers = {{
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }};
            if (isLoggedIn) {{
                const username = document.cookie.replace(/(?:(?:^|.*;\\s*)username\\s*=\\s*([^;]*).*$)|^.*$/, "$1");
                const password = document.cookie.replace(/(?:(?:^|.*;\\s*)password\\s*=\\s*([^;]*).*$)|^.*$/, "$1");
                if (username && password) {{
                    headers['Authorization'] = 'Basic ' + btoa(username + ':' + password);
                }}
            }}
            fetch(url, {{
                method: method,
                headers: headers,
                body: JSON.stringify(data)
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.status === 'success') {{
                    if (!isLoggedIn) {{
                        showCredentials(data.credentials, data.profile_url);
                    }} else {{
                        alert('Данные успешно обновлены');
                    }}
                }} else {{
                    if (data.errors) {{
                        displayServerErrors(data.errors);
                    }} else {{
                        alert(data.message || 'Произошла ошибка');
                    }}
                }}
            }})
            .catch(error => {{
                console.error('API error:', error);
                form.submit();
            }});
        }}

        function displayServerErrors(errors) {{
            document.querySelectorAll('.error-message').forEach(el => el.textContent = '');
            document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
            for (const field in errors) {{
                const errorElement = document.querySelector(`span.${{field}}_error`);
                const inputElement = document.querySelector(`[name="${{field}}"]`) || 
                                   document.querySelector(`[name="${{field}}[]"]`);
                if (errorElement) {{
                    errorElement.textContent = errors[field];
                }}
                if (inputElement) {{
                    inputElement.classList.add('error');
                }}
            }}
        }}

        function showCredentials(credentials, profileUrl) {{
            const credentialsDiv = document.createElement('div');
            credentialsDiv.className = 'credentials';
            credentialsDiv.innerHTML = `
                <h3>Ваши учетные данные (сохраните их):</h3>
                <p><strong>Логин:</strong> ${{credentials.username}}</p>
                <p><strong>Пароль:</strong> ${{credentials.password}}</p>
                <p><strong>Ссылка на профиль:</strong> ${{profileUrl}}</p>
            `;
            document.cookie = `username=${{credentials.username}}; path=/`;
            document.cookie = `password=${{credentials.password}}; path=/`;
            form.parentNode.insertBefore(credentialsDiv, form);
            const logoutForm = document.createElement('form');
            logoutForm.id = 'logoutForm';
            logoutForm.action = 'submit_form.py';
            logoutForm.method = 'POST';
            logoutForm.innerHTML = `
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="logout-button">Выйти</button>
            `;
            form.parentNode.insertBefore(logoutForm, form.nextSibling);
            document.querySelector('.login-section').style.display = 'none';
        }}
    }});
    """

    context = {
        'last_name': escape_html(data.get('last_name', '')),
        'first_name': escape_html(data.get('first_name', '')),
        'patronymic': escape_html(data.get('patronymic', '')),
        'phone': escape_html(data.get('phone', '')),
        'email': escape_html(data.get('email', '')),
        'birthdate': escape_html(data.get('birthdate', '')),
        'male_checked': 'checked' if data.get('gender') == 'male' else '',
        'female_checked': 'checked' if data.get('gender') == 'female' else '',
        'pascal_selected': 'selected' if 'Pascal' in data.get('languages', []) else '',
        'c_selected': 'selected' if 'C' in data.get('languages', []) else '',
        'cpp_selected': 'selected' if 'C++' in data.get('languages', []) else '',
        'javascript_selected': 'selected' if 'JavaScript' in data.get('languages', []) else '',
        'php_selected': 'selected' if 'PHP' in data.get('languages', []) else '',
        'python_selected': 'selected' if 'Python' in data.get('languages', []) else '',
        'java_selected': 'selected' if 'Java' in data.get('languages', []) else '',
        'haskel_selected': 'selected' if 'Haskel' in data.get('languages', []) else '',
        'clojure_selected': 'selected' if 'Clojure' in data.get('languages', []) else '',
        'prolog_selected': 'selected' if 'Prolog' in data.get('languages', []) else '',
        'scala_selected': 'selected' if 'Scala' in data.get('languages', []) else '',
        'go_selected': 'selected' if 'Go' in data.get('languages', []) else '',
        'bio': escape_html(data.get('bio', '')),
        'contract_checked': 'checked' if data.get('contract') else '',
        'last_name_error': escape_html(errors.get('last_name', '')),
        'first_name_error': escape_html(errors.get('first_name', '')),
        'patronymic_error': escape_html(errors.get('patronymic', '')),
        'phone_error': escape_html(errors.get('phone', '')),
        'email_error': escape_html(errors.get('email', '')),
        'birthdate_error': escape_html(errors.get('birthdate', '')),
        'gender_error': escape_html(errors.get('gender', '')),
        'languages_error': escape_html(errors.get('languages', '')),
        'bio_error': escape_html(errors.get('bio', '')),
        'contract_error': escape_html(errors.get('contract', '')),
        'last_name_error_class': 'error' if 'last_name' in errors else '',
        'first_name_error_class': 'error' if 'first_name' in errors else '',
        'patronymic_error_class': 'error' if 'patronymic' in errors else '',
        'phone_error_class': 'error' if 'phone' in errors else '',
        'email_error_class': 'error' if 'email' in errors else '',
        'birthdate_error_class': 'error' if 'birthdate' in errors else '',
        'bio_error_class': 'error' if 'bio' in errors else '',
        'csrf_token': csrf_token_value,
        'login_section': login_section,
        'credentials_section': credentials_section,
        'logout_button': logout_button,
        'script': script
    }

    html_template = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Форма</title>
        <link rel="stylesheet" href="styles.css">
        <script>
            {script}
        </script>
    </head>
    <body>
        {login_section}
        {credentials_section}
        {logout_button}
        <form id="mainForm" action="submit_form.py" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <label for="last_name">Фамилия:</label>
            <input type="text" id="last_name" name="last_name" maxlength="50" required
                   value="{last_name}" class="{last_name_error_class}">
            <span class="error-message last_name_error">{last_name_error}</span><br>

            <label for="first_name">Имя:</label>
            <input type="text" id="first_name" name="first_name" maxlength="50" required
                   value="{first_name}" class="{first_name_error_class}">
            <span class="error-message first_name_error">{first_name_error}</span><br>

            <label for="patronymic">Отчество:</label>
            <input type="text" id="patronymic" name="patronymic" maxlength="50"
                   value="{patronymic}" class="{patronymic_error_class}">
            <span class="error-message patronymic_error">{patronymic_error}</span><br>

            <label for="phone">Телефон:</label>
            <input type="tel" id="phone" name="phone" maxlength="15"
                   value="{phone}" class="{phone_error_class}">
            <span class="error-message phone_error">{phone_error}</span><br>

            <label for="email">Email:</label>
            <input type="email" id="email" name="email" maxlength="100" required
                   value="{email}" class="{email_error_class}">
            <span class="error-message email_error">{email_error}</span><br>

            <label for="birthdate">Дата рождения:</label>
            <input type="date" id="birthdate" name="birthdate" required
                   value="{birthdate}" class="{birthdate_error_class}">
            <span class="error-message birthdate_error">{birthdate_error}</span><br>

            <label>Пол:</label>
            <label><input type="radio" name="gender" value="male" {male_checked}> Мужской</label>
            <label><input type="radio" name="gender" value="female" {female_checked}> Женский</label>
            <span class="error-message gender_error">{gender_error}</span><br>

            <label for="languages">Любимые языки программирования:</label>
            <select name="languages[]" id="languages" multiple size="5">
                <option value="Pascal" {pascal_selected}>Pascal</option>
                <option value="C" {c_selected}>C</option>
                <option value="C++" {cpp_selected}>C++</option>
                <option value="JavaScript" {javascript_selected}>JavaScript</option>
                <option value="PHP" {php_selected}>PHP</option>
                <option value="Python" {python_selected}>Python</option>
                <option value="Java" {java_selected}>Java</option>
                <option value="Haskel" {haskel_selected}>Haskel</option>
                <option value="Clojure" {clojure_selected}>Clojure</option>
                <option value="Prolog" {prolog_selected}>Prolog</option>
                <option value="Scala" {scala_selected}>Scala</option>
                <option value="Go" {go_selected}>Go</option>
            </select>
            <span class="error-message languages_error">{languages_error}</span><br>

            <label for="bio">Биография:</label>
            <textarea id="bio" name="bio" rows="4" cols="40" class="{bio_error_class}">{bio}</textarea>
            <span class="error-message bio_error">{bio_error}</span><br>

            <label><input type="checkbox" name="contract" {contract_checked}> С контрактом ознакомлен(а)</label>
            <span class="error-message contract_error">{contract_error}</span><br>

            <button type="submit">Сохранить</button>
        </form>
        <noscript>
            <style>#mainForm {{ display: block !important; }}</style>
            <p>Для работы с формой требуется JavaScript. Пожалуйста, включите JavaScript в вашем браузере.</p>
        </noscript>
    </body>
    </html>
    """.format(**context)

    return html_template

def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    return True

def generate_credentials():
    username = secrets.token_hex(8)
    password = secrets.token_hex(8)
    return {'username': username, 'password': password}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_user_data(connection, data, credentials=None):
    cursor = connection.cursor()
    try:
        if credentials:
            cursor.execute("""
                UPDATE applications 
                SET last_name=%s, first_name=%s, patronymic=%s, phone=%s, email=%s, 
                    birthdate=%s, gender=%s, bio=%s, contract=%s
                WHERE username=%s
            """, (
                data['last_name'], data['first_name'], data['patronymic'],
                data['phone'], data['email'], data['birthdate'],
                data['gender'], data['bio'], data['contract'],
                credentials['username']
            ))
            cursor.execute("SELECT id FROM applications WHERE username=%s", (credentials['username'],))
            result = cursor.fetchone()
            application_id = result['id'] if result else None
        else:
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
        return credentials

    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(f"<h1>Ошибка базы данных.</h1>")
        connection.rollback()
        return None
    except Exception as e:
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(f"<h1>Ошибка.</h1>")
        connection.rollback()
        return None
    finally:
        cursor.close()

def verify_user(connection, username, password):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT id, password_hash FROM applications WHERE username=%s
        """, (username,))
        result = cursor.fetchone()
        if result:
            hashed_password = hash_password(password)
            if result['password_hash'] == hashed_password:
                return True
        return False
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(f"<h1>Ошибка при аутентификации пользователя.</h1>")
        return None
    finally:
        cursor.close()

def get_user_data(connection, username):
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
            return None
        data = {
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
        return data
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(f"<h1>Ошибка при загрузке данных пользователя.</h1>")
        return None
    finally:
        cursor.close()

if __name__ == "__main__":
    cookie = http.cookies.SimpleCookie()
    cookie.load(os.environ.get('HTTP_COOKIE', ''))
    form = cgi.FieldStorage()
    request_method = os.environ.get('REQUEST_METHOD', '')
    action = form.getvalue('action')
    csrf_token = form.getvalue('csrf_token')

    if request_method == 'POST' and not action:
        if not validate_csrf_token(csrf_token):
            print("Content-Type: text/html; charset=utf-8")
            print()
            print("<h1>CSRF-токен недействителен. Попробуйте снова.</h1>")
            exit()

    if action == 'login' and request_method == 'POST':
        username = form.getvalue('username', '').strip()
        password = form.getvalue('password', '').strip()
        connection = create_connection()
        if connection:
            if verify_user(connection, username, password):
                session_id = secrets.token_hex(16)
                cookie['session_id'] = session_id
                cookie['session_id']['path'] = '/'
                cookie['session_id']['expires'] = (datetime.now() + timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cursor = connection.cursor()
                try:
                    cursor.execute(
                        """
                        INSERT INTO sessions (session_id, username, expires_at)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            session_id,
                            username,
                            datetime.now() + timedelta(days=1)
                        )
                    )
                    connection.commit()
                finally:
                    cursor.close()
                print("Content-Type: text/html; charset=utf-8")
                print("Status: 303 See Other")
                print("Location: submit_form.py")
                print(cookie.output())
                print()
                connection.close()
                exit()
            connection.close()
        print("Content-Type: text/html; charset=utf-8")
        print()
        print("<h1>Неверный логин или пароль</h1>")
        exit()

    elif action == 'logout' and request_method == 'POST':
        session_id = cookie.get('session_id')
        if session_id:
            connection = create_connection()
            if connection:
                cursor = connection.cursor()
                try:
                    cursor.execute("""
                        DELETE FROM sessions WHERE session_id=%s
                    """, (session_id.value,))
                    connection.commit()
                finally:
                    cursor.close()
                connection.close()
            cookie['session_id'] = ''
            cookie['session_id']['path'] = '/'
            cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        print("Content-Type: text/html; charset=utf-8")
        print("Status: 303 See Other")
        print("Location: submit_form.py")
        print(cookie.output())
        print()
        exit()

    is_logged_in = False
    username = None
    session_id = cookie.get('session_id')
    if session_id:
        connection = create_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("""
                    SELECT username FROM sessions 
                    WHERE session_id=%s AND expires_at > NOW()
                """, (session_id.value,))
                result = cursor.fetchone()
                if result:
                    is_logged_in = True
                    username = result['username']
            finally:
                cursor.close()
            connection.close()

    data = {
        'last_name': form.getvalue('last_name', '').strip(),
        'first_name': form.getvalue('first_name', '').strip(),
        'patronymic': form.getvalue('patronymic', '').strip(),
        'phone': form.getvalue('phone', '').strip(),
        'email': form.getvalue('email', '').strip(),
        'birthdate': form.getvalue('birthdate', '').strip(),
        'gender': form.getvalue('gender', '').strip(),
        'languages': form.getlist('languages[]'),
        'bio': form.getvalue('bio', '').strip(),
        'contract': 'contract' in form 
    }

    if is_logged_in and not any(data.values()):
        connection = create_connection()
        if connection:
            user_data = get_user_data(connection, username)
            if user_data:
                data.update(user_data)
            connection.close()
    elif not any(data.values()):
        for field in data.keys():
            if field in cookie:
                data[field] = cookie[field].value

    if request_method == 'POST' and not action:
        errors = validate_form(data)
        if errors:
            print("Content-Type: text/html; charset=utf-8")
            print()
            print(generate_html_form(data, errors, is_logged_in))
            exit()
        else:
            for field in data.keys():
                if f'{field}_error' in cookie:
                    del cookie[f'{field}_error']
            for field, value in data.items():
                cookie[field] = value
                cookie[field]['path'] = '/'
                cookie[field]['expires'] = (datetime.now() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
            connection = create_connection()
            if connection:
                if is_logged_in:
                    credentials = insert_user_data(connection, data, {'username': username})
                    success_message = "<h1>Данные успешно обновлены</h1>"
                else:
                    credentials = insert_user_data(connection, data)
                    if credentials:
                        success_message = f"""
                        <h1>Данные успешно сохранены</h1>
                        <div class="credentials">
                            <h3>Ваши учетные данные (сохраните их):</h3>
                            <p><strong>Логин:</strong> {escape_html(credentials['username'])}</p>
                            <p><strong>Пароль:</strong> {escape_html(credentials['password'])}</p>
                        </div>
                        """
                    else:
                        success_message = "<h1>Ошибка при сохранении данных</h1>"
                connection.close()
            else:
                success_message = "<h1>Ошибка подключения к базе данных</h1>"
            print("Content-Type: text/html; charset=utf-8")
            print(cookie.output())
            print()
            print(success_message)
    else:
        credentials = None
        if 'show_credentials' in cookie and cookie['show_credentials'].value == 'true':
            credentials = {
                'username': cookie['username'].value,
                'password': cookie['password'].value
            }
            cookie['show_credentials'] = ''
            cookie['show_credentials']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        print("Content-Type: text/html; charset=utf-8")
        print()
        print(generate_html_form(data, {}, is_logged_in, credentials))
