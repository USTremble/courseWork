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

@app.before_request
def load_user():
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

# ───────── профиль ─────────────────────────────────────────
EVENTS_PER_PAGE=10
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

# ─────────────────────────── PROFILE ──────────────────────────────
EVENTS_PER_PAGE = 10           # оставьте, если уже объявлено выше

@app.route('/profile')
@login_required
def profile():
    uid   = session['user_id']
    page  = max(int(request.args.get('page', 1)), 1)
    off   = (page - 1) * EVENTS_PER_PAGE

    stats = user_stats(uid)

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT is_blocked FROM users WHERE user_id=%s", (uid,))
    is_blocked = cur.fetchone()[0]

    # все команды пользователя
    cur.execute("SELECT team_id FROM team_members WHERE user_id=%s", (uid,))
    team_ids = [r[0] for r in cur.fetchall()]

    # история участия
    # внутри функции profile()   —  вместо предыдущего SELECT history
    cur.execute("""
        SELECT e.event_id,
            e.name,
            e.status,
            NOW() AS ev_date,                -- можно заменить на e.date, если столбец есть
            my_t.team_name,
            win_t.team_name
        FROM events e
        JOIN event_teams my_et   ON my_et.event_id = e.event_id
        JOIN teams      my_t     ON my_t.team_id   = my_et.team_id
        LEFT JOIN LATERAL (
                SELECT t.team_name
                FROM event_teams et JOIN teams t USING(team_id)
                WHERE et.event_id = e.event_id
                ORDER BY et.points DESC
                LIMIT 1
        ) win_t ON TRUE
        WHERE e.status = 'finished'                  -- ←  только завершённые
        AND my_et.team_id = ANY(%s)
        ORDER BY e.event_id DESC
        LIMIT %s OFFSET %s
    """, (team_ids, EVENTS_PER_PAGE, off))
    history = [{
        'date'   : r[3],
        'name'   : r[1],
        'status' : r[2],
        'my_team': r[4],
        'winner' : r[5]
    } for r in cur.fetchall()]


    # всего записей для пагинации
    cur.execute("""SELECT COUNT(*)
                     FROM event_teams
                    WHERE team_id = ANY(%s)""", (team_ids,))
    total = cur.fetchone()[0]
    pages = (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE

    cur.close(); conn.close()

    return render_template('profile.html',
                           page_title='Профиль',
                           stats=stats,
                           is_blocked=is_blocked,
                           history=history,
                           page=page, pages=pages,
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
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("""SELECT t.team_id,t.team_name,t.description
                     FROM teams t JOIN team_members tm ON t.team_id=tm.team_id
                    WHERE tm.user_id=%s""",(session['user_id'],))
    t=cur.fetchone()
    if not t: cur.close(); conn.close(); return None,None
    cur.execute("SELECT u.user_id,u.username FROM users u JOIN team_members tm ON tm.user_id=u.user_id WHERE tm.team_id=%s",(t[0],))
    members=[{'user_id':r[0],'username':r[1]} for r in cur.fetchall()]
    cur.close(); conn.close()
    return {'team_id':t[0],'team_name':t[1],'description':t[2]},members

@app.route('/team')
@login_required
def team():
    ti,mem=current_team()
    return render_template('team.html', page_title='Команда', team=ti, members=mem)

@app.route('/create_team', methods=['POST'])
@login_required
def create_team():
    name = request.form['team_name'].strip()[:32]
    code = (request.form['invite_code'] or '').strip()[:16] or random_code()

    if len(name) < 3:
        flash('Название слишком короткое', 'modal-create-error')
        return redirect(url_for('team'))

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""INSERT INTO teams(team_name,invite_code)
                       VALUES(%s,%s) RETURNING team_id""", (name, code))
        tid = cur.fetchone()[0]
        cur.execute("INSERT INTO team_members(team_id,user_id) VALUES(%s,%s)",
                    (tid, session['user_id']))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash('Имя или код уже заняты', 'modal-create-error')
    finally:
        cur.close(); conn.close()
    return redirect(url_for('team'))


@app.route('/join_team', methods=['POST'])
@login_required
def join_team():
    code = request.form['invite_code'].strip()[:16]
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT team_id FROM teams WHERE invite_code=%s", (code,))
    row = cur.fetchone()
    if row:
        cur.execute("""INSERT INTO team_members(team_id,user_id)
                       VALUES(%s,%s) ON CONFLICT DO NOTHING""",
                    (row[0], session['user_id']))
        conn.commit()
    else:
        flash('Неверный код', 'modal-join-error')
    cur.close(); conn.close()
    return redirect(url_for('team'))


@app.route('/leave_team', methods=['POST'])
@login_required
def leave_team():
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("DELETE FROM team_members WHERE user_id=%s",(session['user_id'],))
    conn.commit(); cur.close(); conn.close(); flash('Команда покинута')
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

# ───── защита от удалённого аккаунта ─────
@app.before_request
def ensure_exists():
    uid = session.get('user_id')
    if uid:
        conn=get_db_connection(); cur=conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE user_id=%s", (uid,))
        if not cur.fetchone():
            session.clear()
        cur.close(); conn.close()
    g.user = session.get('username')

# ─────────────────  СОБЫТИЯ  (игрок) ────────────────
def team_required():
    team, members = current_team()
    if not team:
        flash('Нужно состоять в команде', 'error')
        return None, None
    return team, members

# ─────────────────────────── EVENTS (игрок) ──────────────────────
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

    cur.execute("SELECT answer, status FROM events WHERE event_id=%s", (eid,))
    row = cur.fetchone()
    if not row:
        flash('Событие не найдено', 'error')
    elif row[1] != 'running':
        flash('Приём ответов закрыт', 'error')
    else:
        cur.execute("""INSERT INTO event_submits(event_id, team_id, answer)
                       VALUES (%s,%s,%s)""",
                    (eid, team['team_id'], ans))
        if ans.lower() == row[0].lower():
            cur.execute("""UPDATE event_teams
                              SET points = points + 1
                            WHERE event_id=%s AND team_id=%s""",
                        (eid, team['team_id']))
        conn.commit(); flash('Ответ отправлен')
    cur.close(); conn.close()
    return redirect(url_for('events'))


# ─────────────────  СОБЫТИЯ  (модератор) ─────────────
def moderator_required(view):
    @wraps(view)
    def wrapped(*a,**kw):
        if session.get('role') not in ('moderator','admin'):
            flash('Нужны права модератора','error'); return redirect(url_for('dashboard'))
        return view(*a,**kw)
    return wrapped

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
    ev = None; teams = []
    code_posted = request.form.get('code', '')

    conn = get_db_connection(); cur = conn.cursor()
    if request.method == 'POST':
        code = code_posted[:16]
        cur.execute("SELECT event_id,name,status FROM events WHERE code=%s", (code,))
        ev = cur.fetchone()

        # внутри /mod/manage  ─ после получения ev и before render_template
    if ev:
        eid = ev[0]

        # обработка кнопок
        if 'start' in request.form:
            cur.execute("UPDATE events SET status='running' WHERE event_id=%s", (eid,))
        elif 'finish' in request.form:
            cur.execute("UPDATE events SET status='finished' WHERE event_id=%s", (eid,))
        elif 'pts' in request.form:
            tid  = request.form['tid']
            delta = int(request.form['delta'])
            cur.execute("""UPDATE event_teams
                            SET points = points + %s
                            WHERE event_id = %s AND team_id = %s""",
                        (delta, eid, tid))
        elif 'dq' in request.form:                         # ← дисквалификация
            tid = request.form['tid']
            cur.execute("DELETE FROM event_teams WHERE event_id=%s AND team_id=%s",
                        (eid, tid))
        conn.commit()

        # выборка команд события  (без сортировки по очкам)
        cur.execute("""
            SELECT et.team_id,
                t.team_name,
                et.points,
                COALESCE((SELECT answer
                            FROM event_submits s
                            WHERE s.team_id = et.team_id
                                AND s.event_id = et.event_id
                            ORDER BY ts DESC LIMIT 1),'') AS last_answer,
                COALESCE((SELECT ts
                            FROM event_submits s
                            WHERE s.team_id = et.team_id
                                AND s.event_id = et.event_id
                            ORDER BY ts DESC LIMIT 1),NULL) AS last_ts
            FROM event_teams et
            JOIN teams t USING(team_id)
            WHERE et.event_id = %s
            ORDER BY et.id                                  -- ← сортировка по id
        """, (eid,))
        teams = cur.fetchall()

    cur.close(); conn.close()

    return render_template('mod_manage.html',
                           page_title='Проведение события',
                           ev=ev, teams=teams, code_entered=code_posted)


# ───────── index ────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if g.user else render_template('index.html')

if __name__=='__main__': app.run(debug=True)
