from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2, os

# ────── базовая инициализация ──────
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = '777'                         # в продакшне вынести в переменные среды

def get_db_connection():
    return psycopg2.connect(
        dbname='ib_competition_db',
        user='uster',
        password='1234',
        host='localhost',
        port='5432'
    )

# ────── декораторы ──────
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему.', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Доступ только администратору', 'error')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)
    return wrapped

@app.before_request
def load_logged_user():
    g.user = session.get('username')

# ────── регистрация ──────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm  = request.form['confirm_password']

        if password != confirm:
            flash('Пароли не совпадают!', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            flash('Такой пользователь уже существует!', 'error')
            cur.close(); conn.close(); return redirect(url_for('register'))

        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES (%s, %s, 'player') RETURNING user_id
        """, (username, generate_password_hash(password)))
        session.update({'user_id': cur.fetchone()[0], 'username': username, 'role': 'player'})
        conn.commit(); cur.close(); conn.close()
        flash('Добро пожаловать! Аккаунт создан.')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

# ────── вход / выход ──────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']; password = request.form['password']
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT user_id, password, role FROM users WHERE username=%s", (username,))
        row = cur.fetchone(); cur.close(); conn.close()

        if row and check_password_hash(row[1], password):
            session.update({'user_id': row[0], 'username': username, 'role': row[2]})
            flash('Вход выполнен')
            return redirect(url_for('dashboard'))
        flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Вы вышли из системы.')
    return redirect(url_for('index'))

# ────── главные страницы ──────
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', page_title='Главная')

@app.route('/events')
@login_required
def events():
    return render_template('events.html', page_title='События')

# ────── профиль игрока ──────
EVENTS_PER_PAGE = 10
def user_stats(uid):
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT COUNT(*), SUM(CASE WHEN is_winner THEN 1 ELSE 0 END) "
                "FROM event_participants WHERE user_id=%s", (uid,))
    total, wins = cur.fetchone()
    cur.close(); conn.close()
    return {'total': total or 0, 'wins': wins or 0}

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    page = max(int(request.args.get('page', 1)), 1)
    offset = (page - 1) * EVENTS_PER_PAGE

    stats = user_stats(session['user_id'])

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT e.date, e.name, mt.team_name, wt.team_name
        FROM events e
        JOIN event_participants ep ON ep.event_id = e.event_id
        JOIN teams mt ON mt.team_id = ep.team_id
        JOIN teams wt ON wt.team_id = e.winner_team_id
        WHERE ep.user_id = %s
        ORDER BY e.date DESC
        LIMIT %s OFFSET %s
    """, (session['user_id'], EVENTS_PER_PAGE, offset))
    history = [{'date': r[0], 'name': r[1], 'my_team': r[2], 'winner': r[3]} for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM event_participants WHERE user_id=%s", (session['user_id'],))
    total = cur.fetchone()[0]; pages = (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE
    cur.close(); conn.close()

    return render_template('profile.html', page_title='Профиль',
                           stats=stats, history=history, page=page, pages=pages)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old = request.form['old']; new = request.form['new']
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE user_id=%s", (session['user_id'],))
    if check_password_hash(cur.fetchone()[0], old):
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s",
                    (generate_password_hash(new), session['user_id']))
        conn.commit(); flash('Пароль обновлён')
    else:
        flash('Старый пароль неверен', 'error')
    cur.close(); conn.close()
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    pwd = request.form['pwd']
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE user_id=%s", (session['user_id'],))
    if check_password_hash(cur.fetchone()[0], pwd):
        cur.execute("DELETE FROM users WHERE user_id=%s", (session['user_id'],))
        conn.commit(); session.clear(); flash('Аккаунт удалён')
        return redirect(url_for('index'))
    flash('Пароль неверен', 'error'); return redirect(url_for('profile'))

# ────── работа с командами ──────
def current_team():
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("""SELECT t.team_id,t.team_name,t.description
                   FROM teams t JOIN team_members tm ON t.team_id=tm.team_id
                   WHERE tm.user_id=%s""", (session['user_id'],))
    team = cur.fetchone()
    if not team:
        cur.close(); conn.close(); return None, None
    cur.execute("""SELECT u.user_id,u.username
                   FROM users u JOIN team_members tm ON tm.user_id=u.user_id
                   WHERE tm.team_id=%s""", (team[0],))
    members = [{'user_id': r[0], 'username': r[1]} for r in cur.fetchall()]
    cur.close(); conn.close()
    return {'team_id': team[0], 'team_name': team[1], 'description': team[2]}, members

@app.route('/team', methods=['GET'])
@login_required
def team():
    team_info, members = current_team()
    return render_template('team.html', page_title='Команда',
                           team=team_info, members=members)

@app.route('/create_team', methods=['POST'])
@login_required
def create_team():
    name = request.form['team_name']; desc = request.form['description']; code = request.form['invite_code']
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO teams (team_name, description, invite_code) VALUES (%s, %s, %s) RETURNING team_id",
                    (name, desc, code))
        tid = cur.fetchone()[0]
        cur.execute("INSERT INTO team_members (team_id, user_id) VALUES (%s, %s)", (tid, session['user_id']))
        conn.commit(); flash('Команда создана')
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); flash('Имя команды или код уже существуют', 'error')
    finally:
        cur.close(); conn.close()
    return redirect(url_for('team'))

@app.route('/join_team', methods=['POST'])
@login_required
def join_team():
    code = request.form['invite_code']
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT team_id FROM teams WHERE invite_code=%s", (code,))
    row = cur.fetchone()
    if row:
        cur.execute("""
            INSERT INTO team_members (team_id, user_id)
            VALUES (%s, %s) ON CONFLICT DO NOTHING
        """, (row[0], session['user_id']))
        conn.commit(); flash('Вы присоединились к команде')
    else:
        flash('Неверный код приглашения', 'error')
    cur.close(); conn.close()
    return redirect(url_for('team'))

@app.route('/leave_team', methods=['POST'])
@login_required
def leave_team():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM team_members WHERE user_id=%s", (session['user_id'],))
    conn.commit(); cur.close(); conn.close()
    flash('Вы покинули команду')
    return redirect(url_for('team'))

# ────── admin: таблицы ──────
PER_PAGE = 10

@app.route('/admin/users')
@admin_required
def admin_users():
    page = max(int(request.args.get('page', 1)), 1)
    q    = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'user_id')
    order= request.args.get('dir', 'asc')
    allowed = {'user_id', 'username', 'role'}
    if sort not in allowed: sort = 'user_id'
    order_sql = 'ASC' if order == 'asc' else 'DESC'

    base_sql = """
        SELECT u.user_id, u.username,
               COALESCE(string_agg(t.team_name || ' (' || t.team_id || ')', ', '), '—') AS teams,
               u.role
        FROM users u
        LEFT JOIN team_members tm ON tm.user_id = u.user_id
        LEFT JOIN teams t ON t.team_id = tm.team_id
    """
    where = ''; params = []
    if q:
        where = ("WHERE CAST(u.user_id AS TEXT) ILIKE %s OR "
                 "u.username ILIKE %s OR t.team_name ILIKE %s")
        params = [f'%{q}%'] * 3
    group = "GROUP BY u.user_id"
    order_by = f"ORDER BY {sort} {order_sql}"
    limit = "LIMIT %s OFFSET %s"
    params += [PER_PAGE, (page - 1) * PER_PAGE]

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"{base_sql} {where} {group} {order_by} {limit}", params)
    users = cur.fetchall()
    cur.execute(f"SELECT COUNT(DISTINCT u.user_id) FROM users u "
                f"LEFT JOIN team_members tm ON TRUE {where}", params[:-2])
    total = cur.fetchone()[0]; pages = (total + PER_PAGE - 1) // PER_PAGE
    cur.close(); conn.close()

    return render_template('admin_users.html', page_title='Пользователи',
                           users=users, page=page, pages=pages,
                           q=q, sort=sort, order=order)

@app.route('/admin/teams')
@admin_required
def admin_teams():
    page = max(int(request.args.get('page', 1)), 1)
    q    = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'team_id')
    order= request.args.get('dir', 'asc')
    allowed = {'team_id', 'team_name', 'members'}
    if sort not in allowed: sort = 'team_id'
    order_sql = 'ASC' if order == 'asc' else 'DESC'

    base_sql = """
        SELECT t.team_id, t.team_name,
               COALESCE(string_agg(tm.user_id::TEXT, ', '), '') AS member_ids,
               COUNT(tm.user_id) AS members
        FROM teams t
        LEFT JOIN team_members tm ON tm.team_id = t.team_id
    """
    where = ''; params = []
    if q:
        where = ("WHERE CAST(t.team_id AS TEXT) ILIKE %s OR "
                 "t.team_name ILIKE %s OR CAST(tm.user_id AS TEXT) ILIKE %s")
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
    total = cur.fetchone()[0]; pages = (total + PER_PAGE - 1) // PER_PAGE
    cur.close(); conn.close()

    return render_template('admin_teams.html', page_title='Команды',
                           teams=teams, page=page, pages=pages,
                           q=q, sort=sort, order=order)

# ────── admin‑действия ──────
@app.route('/admin/user_action', methods=['POST'])
@admin_required
def admin_user_action():
    uid = request.form['uid']; act = request.form['act']
    conn = get_db_connection(); cur = conn.cursor()
    if act == 'delete':
        cur.execute("DELETE FROM users WHERE user_id=%s", (uid,))
    elif act == 'moder':
        cur.execute("UPDATE users SET role='moderator' WHERE user_id=%s", (uid,))
    elif act == 'toggle':
        cur.execute("UPDATE users SET is_blocked = NOT is_blocked WHERE user_id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/team_action', methods=['POST'])
@admin_required
def admin_team_action():
    tid = request.form['tid']; act = request.form['act']
    conn = get_db_connection(); cur = conn.cursor()
    if act == 'delete':
        cur.execute("DELETE FROM teams WHERE team_id=%s", (tid,))
    elif act == 'disband':
        cur.execute("DELETE FROM team_members WHERE team_id=%s", (tid,))
    elif act == 'kick':
        uid = request.form.get('uid')
        if uid:
            cur.execute("DELETE FROM team_members WHERE team_id=%s AND user_id=%s", (tid, uid))
    conn.commit(); cur.close(); conn.close()
    return redirect(request.referrer or url_for('admin_teams'))

# ────── публичная корневая ──────
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if g.user else render_template('index.html')

# ────── запуск ──────
if __name__ == '__main__':
    app.run(debug=True)
