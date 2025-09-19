from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import json
import os
import secrets
from datetime import datetime

# 載入 .env 設定
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecret")

# Login 管理設定
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# 使用者資料儲存
USER_DB = 'users.json'
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False, indent=2)

def load_users():
    try:
        with open(USER_DB, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_users(users):
    with open(USER_DB, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

# 表單資料儲存
FORMS_FILE = 'forms.json'
if not os.path.exists(FORMS_FILE):
    with open(FORMS_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f, ensure_ascii=False, indent=2)

def load_forms():
    try:
        with open(FORMS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_forms(forms):
    with open(FORMS_FILE, 'w', encoding='utf-8') as f:
        json.dump(forms, f, ensure_ascii=False, indent=2)

# 使用者類別
class User(UserMixin):
    def __init__(self, id_, username, email):
        self.id = id_
        self.username = username
        self.email = email

    @staticmethod
    def get(user_id):
        users = load_users()
        if user_id in users:
            u = users[user_id]
            return User(user_id, u.get('username'), u.get('email'))
        return None

    @staticmethod
    def create(id_, username, email):
        users = load_users()
        users[id_] = {'username': username, 'email': email}
        save_users(users)
        return User(id_, username, email)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# 註冊 OAuth (Google)
oauth = OAuth(app)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# 路由區

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home.html', username=current_user.username, email=current_user.email, now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username].get('password') == password:
            user = User(username, username, users[username].get('email', ''))
            login_user(user)
            flash('登入成功 ✔️', 'success')
            return redirect(url_for('home'))
        else:
            flash('帳號或密碼錯誤 ❗', 'danger')
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    nonce = secrets.token_urlsafe(16)
    session['oauth_nonce'] = nonce
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/login/google/authorized')
def authorize_google():
    token = oauth.google.authorize_access_token()
    if token is None:
        flash('Google 登入失敗 ❗', 'danger')
        return redirect(url_for('login'))

    saved_nonce = session.get('oauth_nonce')
    try:
        user_info = oauth.google.parse_id_token(token, nonce=saved_nonce)
    except Exception as e:
        flash('ID token 驗證失敗 ❗', 'danger')
        return redirect(url_for('login'))

    google_id = user_info['sub']
    email = user_info.get('email')
    name = user_info.get('name')

    users = load_users()
    if google_id in users:
        user = User.get(google_id)
    else:
        user = User.create(google_id, name, email)
    login_user(user)
    flash('Google 登入成功 ✔️', 'success')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        confirm = request.form.get('confirm')
        if password != confirm:
            flash('密碼不一致 ❗', 'danger')
        elif username in users:
            flash('帳號已存在 ❗', 'danger')
        else:
            users[username] = {'username': username, 'password': password, 'email': ''}
            save_users(users)
            flash('註冊成功 ✔️ 請登入', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已登出 🙌', 'success')
    return redirect(url_for('login'))

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.username, now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/service')
@login_required
def service():
    return render_template('service.html')

@app.route('/form', methods=['GET'])
@login_required
def form():
    return render_template('form.html')

@app.route('/form', methods=['POST'])
@login_required
def submit_form():
    name = request.form.get('name')
    form_type = request.form.get('type')
    message = request.form.get('message')
    new_item = {
        'name': name,
        'type': form_type,
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    forms = load_forms()
    forms.append(new_item)
    save_forms(forms)
    flash('表單已提交 ✔️', 'success')
    return redirect(url_for('form'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html', username=current_user.username, email=current_user.email)

@app.route('/admin')
@login_required
def admin():
    forms = load_forms()
    return render_template('admin.html', forms=forms)

@app.route('/so')
@login_required
def so():
    return render_template('so.html')


if __name__ == '__main__':
    app.run(debug=True)
