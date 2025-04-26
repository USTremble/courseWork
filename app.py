from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2, psycopg2.errors
import os, random, string

# ========== инициализация Flask ==========
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = '777'

# ========== директория для PDF-заданий ==========
UPLOAD_DIR = os.path.join(app.static_folder, 'tasks')
os.makedirs(UPLOAD_DIR, exist_ok=True)

EVENTS_PER_PAGE = 10           # оставьте, если уже объявлено выше

def get_db_connection():
    return psycopg2.connect(
        dbname='competition',
        user='uster',
        password='1234',
        host='localhost',
        port='5432'
    )

def random_code(n=6):            # пригодится, если пользователь не ввёл код
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

# ───────── helpers ──────────────────────────────────────────
def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*a, **kw)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if session.get('role') != 'admin':
            flash('Требуются права администратора', 'error')
            return redirect(url_for('dashboard'))
        return view(*a, **kw)
    return wrapped

# ───────── moderator_required (модератор ИЛИ админ) ─────────
def moderator_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        role = session.get('role')
        if role not in ('moderator', 'admin'):
            flash('Требуются права модератора', 'error')
            return redirect(url_for('dashboard'))
        return view(*a, **kw)
    return wrapped


# ────────────────────────── sync_user before-request ──────────────────────────
@app.before_request
def sync_user():
    """
    • Если пользователь залогинен, подтягиваем его актуальную роль
      и флаг блокировки из БД, чтобы sidebar и доступы были корректны.
    • Если запись в БД удалена / не найдена — очищаем сессию.
    • Для шаблонов кладём имя пользователя в g.user  (может быть None).
    """
    uid = session.get('user_id')
    if uid:
        conn = get_db_connection(); cur = conn.cursor()

        cur.execute("SELECT role, is_blocked, username FROM users WHERE user_id=%s", (uid,))
        row = cur.fetchone()

        if row:
            session['role']       = row[0]         # 'player' / 'moderator' / 'admin'
            session['is_blocked'] = row[1]         # True / False
            session['username']   = row[2]
        else:                                     # пользователь удалён
            session.clear()

        cur.close(); conn.close()

    # g.user используется в base.html для отображения имени рядом с аватаркой
    g.user = session.get('username')


# ───────── регистрация / вход ──────────────────────────────
MAX_LOGIN = 32
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        u, p, c = request.form['username'].strip(), request.form['password'], request.form['confirm_password']
        if p != c:
            error = 'Пароли не совпадают'
        elif len(u) > MAX_LOGIN:
            error = f'Максимальна длина логина {MAX_LOGIN}'
        else:
            conn = get_db_connection(); cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=%s", (u,))
            if cur.fetchone():
                error = 'Такой пользователь уже существует'
            else:
                cur.execute("INSERT INTO users (username,password,role) VALUES (%s,%s,'player') RETURNING user_id",
                            (u, generate_password_hash(p)))
                session.update({'user_id':cur.fetchone()[0],'username':u,'role':'player'})
                conn.commit(); cur.close(); conn.close()
                return redirect(url_for('dashboard'))
            cur.close(); conn.close()
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error=None
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        conn=get_db_connection(); cur=conn.cursor()
        cur.execute("SELECT user_id,password,role FROM users WHERE username=%s",(u,))
        row=cur.fetchone(); cur.close(); conn.close()
        if row and check_password_hash(row[1], p):
            session.update({'user_id':row[0],'username':u,'role':row[2]})
            return redirect(url_for('dashboard'))
        error='Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))

# ───────── главная ─────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', page_title='Главная')


# ─────────────────────────── user_stats ───────────────────────────
def user_stats(uid: int) -> dict:
    """
    Возвращает {'total': N, 'wins': M}
    total – количество событий, где участвовали команды игрока
    wins  – сколько раз его команда была первой по очкам
    """
    conn = get_db_connection(); cur = conn.cursor()

    # все команды пользователя
    cur.execute("SELECT team_id FROM team_members WHERE user_id=%s", (uid,))
    team_ids = [r[0] for r in cur.fetchall()]
    if not team_ids:
        cur.close(); conn.close()
        return {'total': 0, 'wins': 0}

    # всего событий
    cur.execute("""SELECT COUNT(DISTINCT event_id)
                     FROM event_teams
                    WHERE team_id = ANY(%s)""", (team_ids,))
    total = cur.fetchone()[0]

    # число побед (событие в статусе finished + макс. очки)
    cur.execute("""
        SELECT COUNT(*)
          FROM events e
          JOIN LATERAL (
               SELECT et.team_id
                 FROM event_teams et
                WHERE et.event_id = e.event_id
                ORDER BY et.points DESC
                LIMIT 1
          ) win ON TRUE
         WHERE e.status = 'finished'
           AND win.team_id = ANY(%s)
    """, (team_ids,))
    wins = cur.fetchone()[0]

    cur.close(); conn.close()
    return {'total': total, 'wins': wins}

# ───────── профиль ─────────
@app.route('/profile')
@login_required
def profile():
    """
    Показывает сведения об учётной записи:
    • имя, роль, статус (активен / заблокирован)
    • ссылку на текущую команду (если есть)
    • формы смены пароля и удаления аккаунта
    """
    username = session.get('username')
    role     = session.get('role')         # player / moderator / admin
    blocked  = session.get('is_blocked', False)

    team, _ = current_team()               # None, [] если не в команде

    return render_template('profile.html',
                           page_title='Профиль',
                           username=username,
                           role=role,
                           is_blocked=blocked,
                           team=team,
                           pass_msg=request.args.get('pm'),
                           pass_ok=request.args.get('ok') == '1')




@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old,new=request.form['old'],request.form['new']
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT password FROM users WHERE user_id=%s",(session['user_id'],))
    if check_password_hash(cur.fetchone()[0],old):
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s",
                    (generate_password_hash(new),session['user_id']))
        conn.commit(); msg,ok='Пароль обновлён','1'
    else:
        msg,ok='Старый пароль неверен','0'
    cur.close(); conn.close()
    return redirect(url_for('profile', pm=msg, ok=ok))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    pwd=request.form['pwd']
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT password FROM users WHERE user_id=%s",(session['user_id'],))
    if check_password_hash(cur.fetchone()[0],pwd):
        cur.execute("DELETE FROM users WHERE user_id=%s",(session['user_id'],))
        conn.commit(); session.clear(); cur.close(); conn.close()
        return redirect(url_for('index'))
    cur.close(); conn.close()
    return redirect(url_for('profile', pm='Пароль неверен', ok='0'))

# ───────── команды игрока ─────────────────────────────────
def current_team():
    conn = get_db_connection(); cur = conn.cursor()

    cur.execute("""
        SELECT t.team_id, t.team_name, t.description
          FROM teams t
          JOIN team_members tm ON t.team_id = tm.team_id
         WHERE tm.user_id=%s AND tm.active = TRUE
    """, (session['user_id'],))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return None, []

    cur.execute("""
        SELECT u.user_id, u.username
          FROM users u
          JOIN team_members tm ON u.user_id = tm.user_id
         WHERE tm.team_id = %s AND tm.active = TRUE
    """, (row[0],))
    members = [{'user_id': r[0], 'username': r[1]} for r in cur.fetchall()]

    cur.close(); conn.close()
    return {'team_id': row[0], 'team_name': row[1], 'description': row[2]}, members

@app.route('/team')
@login_required
def team():
    ti, members = current_team()
    # формы «создать / присоединиться» остаются прежними — показываем их,
    # если команды нет
    if not ti:
        return render_template('team.html',
                               page_title='Команда',
                               team=None, members=[])

    # ─── статистика и история ───
    uid   = session['user_id']
    page  = max(int(request.args.get('page', 1)), 1)
    off   = (page - 1) * EVENTS_PER_PAGE

    conn  = get_db_connection(); cur = conn.cursor()
    stats = user_stats(uid)
    history, total = fetch_history(cur, uid, EVENTS_PER_PAGE, off)
    cur.close(); conn.close()
    pages = (total + EVENTS_PER_PAGE - 1)//EVENTS_PER_PAGE

    return render_template('team.html',
                           page_title='Команда',
                           team=ti, members=members,
                           stats=stats, history=history,
                           page=page, pages=pages)

# ───────── история игрока (по событиям) ─────────
def fetch_history(cur, uid: int, limit: int, off: int):
    """
    Возвращает (history_list, total_rows), где history_list —
    список словарей: {'date', 'name', 'my_team', 'winner'}
    """
    SQL = """
        SELECT e.event_id,
               e.name,
               COALESCE(e.finished_at, NOW())        AS dt,
               t.team_name                           AS my_team,
               win.team_name                         AS winner
          FROM events         e
          JOIN event_submits  s  ON s.event_id = e.event_id
          JOIN teams          t  ON t.team_id  = s.team_id
          LEFT JOIN LATERAL (
                SELECT t2.team_name
                  FROM event_teams et2
                  JOIN teams t2 USING(team_id)
                 WHERE et2.event_id = e.event_id
                 ORDER BY et2.points DESC LIMIT 1
          ) win ON TRUE
         WHERE s.user_id = %s
           AND e.status  = 'finished'
         GROUP BY e.event_id,e.name,dt,my_team,winner
         ORDER BY e.event_id DESC
         LIMIT %s OFFSET %s
    """

    try:
        cur.execute(SQL, (uid, limit, off))
    except psycopg2.errors.UndefinedColumn:
        # поля finished_at нет — делаем резервную выборку без него
        cur.connection.rollback()
        SQL_fallback = SQL.replace("COALESCE(e.finished_at, NOW())", "NOW()")
        cur.execute(SQL_fallback, (uid, limit, off))

    rows = cur.fetchall()
    history = [{'date': r[2], 'name': r[1],
                'my_team': r[3], 'winner': r[4]} for r in rows]

    # сколько всего событий в истории
    cur.execute("""
        SELECT COUNT(DISTINCT e.event_id)
          FROM events e JOIN event_submits s ON s.event_id = e.event_id
         WHERE s.user_id = %s AND e.status = 'finished'
    """, (uid,))
    total = cur.fetchone()[0]

    return history, total


# ───── вспомогательная уникальная строка для invite_code ─────
def unique_code(conn, length=6):
    import random, string
    cur = conn.cursor()
    while True:
        code = ''.join(random.choices(string.ascii_uppercase+string.digits, k=length))
        cur.execute("SELECT 1 FROM teams WHERE invite_code=%s", (code,))
        if not cur.fetchone():
            return code

# ───────────────────── СОЗДАТЬ КОМАНДУ ──────────────────────
@app.route('/create_team', methods=['POST'])
@login_required
def create_team():
    if session.get('is_blocked'):
        flash('Аккаунт заблокирован', 'modal-create-error')
        return redirect(url_for('team'))

    name = request.form['team_name'].strip()[:32]
    if len(name) < 3:
        flash('Название слишком короткое', 'modal-create-error')
        return redirect(url_for('team'))

    conn = get_db_connection(); cur = conn.cursor()
    code_raw = (request.form['invite_code'] or '').strip()[:16]
    code = code_raw if code_raw else unique_code(conn)

    try:
        cur.execute("INSERT INTO teams(team_name,invite_code) VALUES(%s,%s) RETURNING team_id",
                    (name, code))
        tid = cur.fetchone()[0]

        # upsert: либо создаём, либо переводим пользователя в новую команду
        cur.execute("""
            INSERT INTO team_members(user_id, team_id, active)
                 VALUES (%s, %s, TRUE)
            ON CONFLICT (user_id)
            DO UPDATE SET team_id = EXCLUDED.team_id, active = TRUE
        """, (session['user_id'], tid))

        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash('Имя команды или код уже заняты', 'modal-create-error')
    finally:
        cur.close(); conn.close()

    return redirect(url_for('team'))


# ──────────────────── ПРИСОЕДИНИТЬСЯ К КОМАНДЕ ───────────────────
@app.route('/join_team', methods=['POST'])
@login_required
def join_team():
    if session.get('is_blocked'):
        flash('Аккаунт заблокирован', 'modal-join-error')
        return redirect(url_for('team'))

    code = request.form['invite_code'].strip()[:16]
    conn = get_db_connection(); cur = conn.cursor()

    cur.execute("SELECT team_id FROM teams WHERE invite_code=%s", (code,))
    row = cur.fetchone()
    if not row:
        flash('Неверный код', 'modal-join-error')
    else:
        tid = row[0]
        cur.execute("""
            INSERT INTO team_members(user_id, team_id, active)
                 VALUES (%s, %s, TRUE)
            ON CONFLICT (user_id)
            DO UPDATE SET team_id = EXCLUDED.team_id, active = TRUE
        """, (session['user_id'], tid))
        conn.commit()

    cur.close(); conn.close()
    return redirect(url_for('team'))




# ───────── покинуть команду ─────────
@app.route('/leave_team', methods=['POST'])
@login_required
def leave_team():
    conn = get_db_connection(); cur = conn.cursor()

    # удаляем строку; rowcount – сколько строк затронуто
    cur.execute("DELETE FROM team_members WHERE user_id=%s", (session['user_id'],))
    if cur.rowcount:
        conn.commit()
        flash('Команда покинута')
    else:
        flash('Вы не состоите в команде', 'error')

    cur.close(); conn.close()
    return redirect(url_for('team'))



# ───────── админ таблицы ─────────────────────────────────
PER_PAGE=10

def paginated(sql_count, sql_rows, params, page):
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute(sql_count, params); total=cur.fetchone()[0]
    pages=(total+PER_PAGE-1)//PER_PAGE
    cur.execute(sql_rows, params+[PER_PAGE,(page-1)*PER_PAGE])
    rows=cur.fetchall(); cur.close(); conn.close()
    return rows,pages,total

@app.route('/admin/users')
@admin_required
def admin_users():
    page=max(int(request.args.get('page',1)),1); q=request.args.get('q','').strip()
    sort=request.args.get('sort','user_id'); order=request.args.get('dir','asc')
    if sort not in {'user_id','username','role'}: sort='user_id'
    dir_sql='ASC' if order=='asc' else 'DESC'

    base_from="""FROM users u
                 LEFT JOIN team_members tm ON tm.user_id=u.user_id
                 LEFT JOIN teams t ON t.team_id=tm.team_id"""
    where=''; params=[]
    if q:
        where=("WHERE CAST(u.user_id AS TEXT) ILIKE %s OR u.username ILIKE %s OR t.team_name ILIKE %s")
        params=[f'%{q}%']*3

    sql_count = f"SELECT COUNT(DISTINCT u.user_id) {base_from} {where}"
    sql_rows  = f"""SELECT u.user_id,u.username,
                           COALESCE(string_agg(t.team_name||' ('||t.team_id||')',', '),'—') AS teams,
                           u.role
                    {base_from} {where}
                    GROUP BY u.user_id
                    ORDER BY {sort} {dir_sql}
                    LIMIT %s OFFSET %s"""

    users,pages,_=paginated(sql_count,sql_rows,params,page)
    return render_template('admin_users.html',page_title='Пользователи',
                           users=users,page=page,pages=pages,q=q,
                           sort=sort,order=order)

@app.route('/admin/teams')
@admin_required
def admin_teams():
    page=max(int(request.args.get('page',1)),1); q=request.args.get('q','').strip()
    sort=request.args.get('sort','team_id'); order=request.args.get('dir','asc')
    if sort not in {'team_id','team_name','members'}: sort='team_id'
    dir_sql='ASC' if order=='asc' else 'DESC'

    base_from="""FROM teams t LEFT JOIN team_members tm ON tm.team_id=t.team_id"""
    where=''; params=[]
    if q:
        where=("WHERE CAST(t.team_id AS TEXT) ILIKE %s OR t.team_name ILIKE %s OR CAST(tm.user_id AS TEXT) ILIKE %s")
        params=[f'%{q}%']*3

    sql_count=f"SELECT COUNT(DISTINCT t.team_id) {base_from} {where}"
    sql_rows =f"""SELECT t.team_id,t.team_name,
                         COALESCE(string_agg(tm.user_id::TEXT,', '),'') AS member_ids,
                         COUNT(tm.user_id) AS members
                  {base_from} {where}
                  GROUP BY t.team_id
                  ORDER BY {sort} {dir_sql}
                  LIMIT %s OFFSET %s"""
    teams,pages,_=paginated(sql_count,sql_rows,params,page)
    return render_template('admin_teams.html',page_title='Команды',
                           teams=teams,page=page,pages=pages,q=q,
                           sort=sort,order=order)

# ───────── админ действия ───────────────────────────────
@app.route('/admin/user_action', methods=['POST'])
@admin_required
def admin_user_action():
    uid,act=request.form['uid'],request.form['act']
    conn=get_db_connection(); cur=conn.cursor()
    if act=='delete':
        cur.execute("DELETE FROM users WHERE user_id=%s",(uid,))
        if str(uid)==str(session.get('user_id')): session.clear()
    elif act=='moder':
        cur.execute("UPDATE users SET role='moderator' WHERE user_id=%s",(uid,))
    elif act=='toggle':
        cur.execute("UPDATE users SET is_blocked=NOT is_blocked WHERE user_id=%s",(uid,))
    conn.commit(); cur.close(); conn.close()
    if not session: return redirect(url_for('index'))
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/team_action', methods=['POST'])
@admin_required
def admin_team_action():
    tid,act=request.form['tid'],request.form['act']
    conn=get_db_connection(); cur=conn.cursor()
    if act=='delete':
        cur.execute("DELETE FROM teams WHERE team_id=%s",(tid,))
    elif act=='disband':
        cur.execute("DELETE FROM team_members WHERE team_id=%s",(tid,))
    elif act=='kick':
        uid=request.form.get('kick_uid')
        if uid:
            cur.execute("DELETE FROM team_members WHERE team_id=%s AND user_id=%s",(tid,uid))
    conn.commit(); cur.close(); conn.close()
    return redirect(request.referrer or url_for('admin_teams'))

# ───────────────────────── EVENTS (игрок) ─────────────────────────
@app.route('/events', methods=['GET', 'POST'])
@login_required
def events():
    team, _ = current_team()
    if not team:
        return render_template('events.html',
                               team=None,
                               page_title='События')

    # -------- POST: присоединение по коду --------
    if request.method == 'POST':
        code = request.form['code'][:16]

        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT event_id, status FROM events WHERE code=%s", (code,))
        ev = cur.fetchone()

        if not ev:
            flash('Код не найден', 'modal-join-error')
        elif ev[1] != 'waiting':
            flash('Регистрация закрыта', 'modal-join-error')
        else:
            try:
                cur.execute("""INSERT INTO event_teams(event_id, team_id)
                               VALUES (%s,%s)""", (ev[0], team['team_id']))
                conn.commit()
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                flash('Команда уже участвует', 'modal-join-error')
        cur.close(); conn.close()
        return redirect(url_for('events'))       # PRG-паттерн

    # -------- GET: мои события + лидерборды --------
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT e.event_id,
               e.name,
               e.status,
               e.type,
               e.description,
               et.points,
               e.file_path
          FROM events e
          JOIN event_teams et USING(event_id)
         WHERE et.team_id = %s
    """, (team['team_id'],))
    rows = cur.fetchall()

    events = []
    for r in rows:
        ev = list(r)
        if r[2] in ('running', 'finished'):               # нужна таблица очков
            cur.execute("""SELECT ROW_NUMBER() OVER(ORDER BY points DESC) AS place,
                                  t.team_name,
                                  et.points
                             FROM event_teams et
                             JOIN teams t USING(team_id)
                            WHERE et.event_id=%s
                            ORDER BY et.points DESC""",
                        (r[0],))
            ev.append(cur.fetchall())     # index 7 = leaderboard list
        else:
            ev.append([])                 # пустой лидерборд
        events.append(ev)

    cur.close(); conn.close()

    all_finished = all(ev[2] == 'finished' for ev in events)

    return render_template('events.html',
                           page_title='События',
                           team=team,
                           events=events,
                           all_finished=all_finished)


@app.route('/submit_answer/<int:eid>', methods=['POST'])
@login_required
def submit_answer(eid):
    team, _ = current_team()
    if not team:
        flash('Нужно состоять в команде', 'error')
        return redirect(url_for('events'))

    ans = request.form['answer'].strip()
    conn = get_db_connection(); cur = conn.cursor()

    # проверяем статус
    cur.execute("SELECT answer, status FROM events WHERE event_id=%s", (eid,))
    row = cur.fetchone()
    if not row:
        flash('Событие не найдено', 'error')
        cur.close(); conn.close()
        return redirect(url_for('events'))

    correct, status = row
    if status != 'running':
        flash('Приём ответов закрыт', 'error')
    else:
        # ── фиксируем попытку игрока с user_id  ──
        cur.execute("""INSERT INTO event_submits(event_id, team_id, user_id, answer)
                       VALUES (%s, %s, %s, %s)""",
                    (eid, team['team_id'], session['user_id'], ans))

        # правильный ответ → +1 очко
        if ans.lower() == correct.lower():
            cur.execute("""UPDATE event_teams
                             SET points = points + 1
                           WHERE event_id=%s AND team_id=%s""",
                        (eid, team['team_id']))
        conn.commit()
        flash('Ответ отправлен')

    cur.close(); conn.close()
    return redirect(url_for('events'))

# ─────────────────── СОЗДАТЬ СОБЫТИЕ (модератор) ───────────────────
@app.route('/mod/create', methods=['GET', 'POST'])
@moderator_required
def mod_create():
    msg = None
    if request.method == 'POST':
        code    = request.form['code'][:16] or random_code()
        name    = request.form['name'][:64]
        desc    = request.form['desc']
        ev_type = request.form['ev_type']            # quiz / ctf
        answer  = request.form['answer'].strip()
        pdf     = request.files.get('task')

        # ─── валидация PDF ───
        if not pdf or not pdf.filename.lower().endswith('.pdf'):
            msg = 'Нужен PDF-файл'
        else:
            filename = secure_filename(pdf.filename)            # защищаем имя
            rel_path = os.path.join('tasks', filename)          #   tasks/quiz1.pdf
            abs_path = os.path.join(app.static_folder, rel_path)  # static/tasks/quiz1.pdf
            pdf.save(abs_path)                                  # сохраняем файл

            # ─── вставляем событие ───
            conn = get_db_connection(); cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO events(code,name,description,type,answer,file_path,created_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (code, name, desc, ev_type, answer, rel_path, session['user_id']))
                conn.commit()
                msg = 'Событие создано'
            except psycopg2.errors.UniqueViolation:
                conn.rollback(); msg = 'Код события уже занят'
            finally:
                cur.close(); conn.close()

    return render_template('mod_create.html',
                           page_title='Создать событие',
                           msg=msg)

@app.route('/mod/manage', methods=['GET', 'POST'])
@moderator_required
def mod_manage():
    code = request.values.get('code', '')[:16]          # сохраняем введённый код
    ev   = teams = None

    # ─── POST: любые действия ───
    if request.method == 'POST':
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT event_id,name,status FROM events WHERE code=%s", (code,))
        ev = cur.fetchone()
        if ev:
            eid, _, status = ev
            if 'start' in request.form and status == 'waiting':
                cur.execute("UPDATE events SET status='running' WHERE event_id=%s", (eid,))
            elif 'finish' in request.form and status != 'finished':
                cur.execute("UPDATE events SET status='finished' WHERE event_id=%s", (eid,))

                # ── фиксируем участие всех активных членов команд, если они ещё не отправляли ──
                cur.execute("""
                    INSERT INTO event_submits(event_id,team_id,user_id,answer)
                    SELECT et.event_id, et.team_id, tm.user_id, ''
                    FROM event_teams et
                    JOIN team_members tm ON tm.team_id = et.team_id AND tm.active = TRUE
                    WHERE et.event_id = %s
                    AND NOT EXISTS (
                        SELECT 1 FROM event_submits s
                            WHERE s.event_id = et.event_id
                            AND s.user_id  = tm.user_id)
                """, (eid,))

            elif 'pts' in request.form and status != 'finished':
                tid   = request.form['tid']
                delta = int(request.form['delta'])
                cur.execute("""UPDATE event_teams
                                SET points = points + %s
                            WHERE event_id=%s AND team_id=%s""",
                            (delta, eid, tid))

            conn.commit()
            cur.close(); conn.close()
        # PRG — чтобы на F5 не повторялся POST
        return redirect(url_for('mod_manage', code=code))

    # ─── GET: показать событие ───
    if code:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT event_id,name,status FROM events WHERE code=%s", (code,))
        ev = cur.fetchone()
        if ev:
            eid = ev[0]
            cur.execute("""
                SELECT et.team_id,
                       t.team_name,
                       et.points,
                       COALESCE((SELECT answer FROM event_submits s
                                  WHERE s.team_id=et.team_id AND s.event_id=et.event_id
                                  ORDER BY ts DESC LIMIT 1),'') AS last_answer,
                       COALESCE((SELECT ts FROM event_submits s
                                  WHERE s.team_id=et.team_id AND s.event_id=et.event_id
                                  ORDER BY ts DESC LIMIT 1),NULL) AS last_ts
                  FROM event_teams et
                  JOIN teams t USING(team_id)
                 WHERE et.event_id=%s
                 ORDER BY et.id
            """, (eid,))
            teams = cur.fetchall()
        cur.close(); conn.close()

    return render_template('mod_manage.html',
                           page_title='Проведение события',
                           ev=ev, teams=teams, code_entered=code)


# ───────── index ────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if g.user else render_template('index.html')

if __name__=='__main__': app.run(debug=True)
