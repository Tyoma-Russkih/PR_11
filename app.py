import os
import bleach
import waitress
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, make_response
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from models import db, User, Note
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Защита session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "upgrade-insecure-requests"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['Server'] = 'SecureApp'
    if 'X-Powered-By' in response.headers:
        del response.headers['X-Powered-By']

    
    return response

# Инициализация ORM и CSRF
db.init_app(app)
csrf = CSRFProtect(app)

# Создание таблиц
with app.app_context():
    db.create_all()

# Разрешенные теги и атрибуты (для безопасности)
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'br', 'p']
ALLOWED_ATTRS = {'a': ['href']}

def sanitize(text):
    """Очистка пользовательского ввода от вредного HTML."""
    return bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)

# ----------------- Авторизация -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize(request.form['username'].strip())
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Успешный вход!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize(request.form['username'].strip())
        password = request.form['password'].strip()

        if not username or not password:
            flash('Заполните все поля', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация успешна! Теперь войдите.', 'success')
        return redirect(url_for('login'))

    return render_template('login.html', register=True)

# ----------------- Заметки -----------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    notes = Note.query.filter_by(user_id=user_id).all()
    return render_template('index.html', notes=notes)

@app.route('/add', methods=['POST'])
def add_note():
    if 'user_id' not in session:
        abort(403)

    title = sanitize(request.form['title'].strip())
    content = sanitize(request.form['content'].strip())
    if not title or not content:
        flash('Заполните все поля', 'danger')
        return redirect(url_for('index'))

    note = Note(title=title, content=content, user_id=session['user_id'])
    db.session.add(note)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/edit/<int:note_id>')
def edit_note(note_id):
    if 'user_id' not in session:
        abort(403)

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        abort(403)

    return render_template('edit.html', note=note)

@app.route('/update/<int:note_id>', methods=['POST'])
def update_note(note_id):
    if 'user_id' not in session:
        abort(403)

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        abort(403)

    note.title = sanitize(request.form['title'].strip())
    note.content = sanitize(request.form['content'].strip())
    db.session.commit()
    flash('Заметка обновлена', 'success')

    return redirect(url_for('index'))

@app.route('/delete/<int:note_id>')
def delete_note(note_id):
    if 'user_id' not in session:
        abort(403)

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        abort(403)

    db.session.delete(note)
    db.session.commit()
    flash('Заметка удалена', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
