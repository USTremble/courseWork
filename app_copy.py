from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = '777'

def get_db_connection():
    return psycopg2.connect(
        dbname='ib_competition_db',
        user='uster',
        password='1234',
        host='localhost',
        port='5432'
    )

# ─────────────────────────── auth helpers ────────────────────────
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

@app.before_request
def load_logged_user():
    g.user = session.get('username')

def admin_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*a, **kw):
        if session.get('role') != 'admin':
            flash('Доступ только администратору')
            return redirect(url_for('dashboard'))
        return view(*a, **kw)
    return wrapped

# ─────────────────────────── регистрация ─────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username         = request.form['username']
        password         = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            flash('Такой пользователь уже существует!')
            cur.close(); conn.close()
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)
        try:
            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, 'player') RETURNING user_id
            """, (username, hashed))
            user_id = cur.fetchone()[0]
            conn.commit()
            session.update({'user_id': user_id, 'username': username, 'role': 'player'})
            flash('Добро пожаловать — вы зарегистрированы!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.rollback()
            flash(f'Ошибка регистрации: {e}')
        finally:
            cur.close(); conn.close()
    return render_template('register.html')

# ─────────────────────────── вход / выход ────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT user_id, password, role FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        cur.close(); conn.close()

        if row and check_password_hash(row[1], password):
            session.update({'user_id': row[0], 'username': username, 'role': row[2]})
            flash('Успешный вход!')
            return redirect(url_for('dashboard'))
        flash('Неверный логин или пароль!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Вы вышли из системы.')
    return redirect(url_for('index'))

# ───── верхние (авторизованные) маршруты ─────
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', page_title='Главная')

@app.route('/team')
@login_required
def team():
    return render_template('team.html', page_title='Команда')

@app.route('/events')
@login_required
def events():
    return render_template('events.html', page_title='События')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', page_title='Профиль')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', page_title='Настройки')

# ───── АДМИН‑страницы ─────
PER_PAGE = 10

@app.route('/admin/users')
@admin_required
def admin_users():
    page  = max(int(request.args.get('page', 1)), 1)
    q     = request.args.get('q', '').strip()
    sort  = request.args.get('sort', 'user_id')
    order = request.args.get('dir', 'asc')

    allowed_sort = {'user_id', 'username', 'role'}
    if sort not in allowed_sort: sort = 'user_id'
    order_sql = 'ASC' if order == 'asc' else 'DESC'

    base_sql = """
        SELECT u.user_id, u.username,
               COALESCE(string_agg(t.team_name || ' (' || t.team_id || ')', ', '), '—') AS teams,
               u.role
        FROM users u
        LEFT JOIN team_members tm ON tm.user_id = u.user_id
        LEFT JOIN teams t ON t.team_id = tm.team_id
    """
    where, params = '', []
    if q:
        where = "WHERE CAST(u.user_id AS TEXT) ILIKE %s OR u.username ILIKE %s OR t.team_name ILIKE %s"
        params = [f'%{q}%'] * 3
    group = "GROUP BY u.user_id"
    order_by = f"ORDER BY {sort} {order_sql}"
    limit = "LIMIT %s OFFSET %s"
    params += [PER_PAGE, (page - 1) * PER_PAGE]

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"{base_sql} {where} {group} {order_by} {limit}", params)
    users = cur.fetchall()

    # всего записей (для пагинации)
    cur.execute(f"SELECT COUNT(DISTINCT u.user_id) FROM users u "
                f"LEFT JOIN teams t ON TRUE {where}", params[:-2])
    total = cur.fetchone()[0]
    conn.close()

    pages = (total + PER_PAGE - 1) // PER_PAGE
    return render_template('admin_users.html', page_title='Пользователи',
                           users=users, page=page, pages=pages,
                           q=q, sort=sort, order=order)

@app.route('/admin/teams')
@admin_required
def admin_teams():
    page  = max(int(request.args.get('page', 1)), 1)
    q     = request.args.get('q', '').strip()
    sort  = request.args.get('sort', 'team_id')
    order = request.args.get('dir', 'asc')
    allowed_sort = {'team_id', 'team_name', 'members'}
    if sort not in allowed_sort: sort = 'team_id'
    order_sql = 'ASC' if order == 'asc' else 'DESC'

    base_sql = """
        SELECT t.team_id, t.team_name,
               COALESCE(string_agg(tm.user_id::TEXT, ', '), '') AS member_ids,
               COUNT(tm.user_id) AS members
        FROM teams t
        LEFT JOIN team_members tm ON tm.team_id = t.team_id
    """
    where, params = '', []
    if q:
        where = "WHERE CAST(t.team_id AS TEXT) ILIKE %s OR t.team_name ILIKE %s OR CAST(tm.user_id AS TEXT) ILIKE %s"
        params = [f'%{q}%'] * 3
    group = "GROUP BY t.team_id"
    order_by = f"ORDER BY {sort} {order_sql}"
    limit = "LIMIT %s OFFSET %s"
    params += [PER_PAGE, (page - 1) * PER_PAGE]

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"{base_sql} {where} {group} {order_by} {limit}", params)
    teams = cur.fetchall()

    cur.execute(f"SELECT COUNT(DISTINCT t.team_id) FROM teams t "
                f"LEFT JOIN team_members tm ON tm.team_id = t.team_id {where}", params[:-2])
    total = cur.fetchone()[0]
    conn.close()

    pages = (total + PER_PAGE - 1) // PER_PAGE
    return render_template('admin_teams.html', page_title='Команды',
                           teams=teams, page=page, pages=pages,
                           q=q, sort=sort, order=order)


# ─────────────────────────── публичная корневая ──────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if g.user else render_template('index.html')

# ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)
