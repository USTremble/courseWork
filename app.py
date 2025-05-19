import os, random, string
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import psycopg2
from psycopg2.errors import UniqueViolation
from flask import (
    Flask, request, jsonify, session,
    g, send_from_directory, abort
)

try:
    from flask_cors import CORS         
except ImportError:
    CORS = None

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", "777")
if CORS:
    CORS(app, supports_credentials=True)

UPLOAD_DIR = os.path.join(app.static_folder, "tasks")
os.makedirs(UPLOAD_DIR, exist_ok=True)

EVENTS_PER_PAGE = 10
PER_PAGE        = 10
HIST_PER_PAGE   = 15

def get_db_connection():
    return psycopg2.connect(
        dbname   = os.getenv("DB_NAME", "competition"),
        user     = os.getenv("DB_USER", "uster"),
        password = os.getenv("DB_PASS", "1234"),
        host     = os.getenv("DB_HOST", "localhost"),
        port     = os.getenv("DB_PORT", "5432")
    )

def json_error(code, msg):
    r = jsonify(ok=False, msg=msg); r.status_code = code; return r

# ───── декораторы ─────
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if 'user_id' not in session:
            return json_error(401, "Требуется вход")
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get('role') != 'admin':
            return json_error(403, "Требуются права администратора")
        return f(*a, **kw)
    return w

def moderator_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get('role') not in ('moderator', 'admin'):
            return json_error(403, "Требуются права модератора")
        return f(*a, **kw)
    return w

@app.before_request
def sync_user():
    uid = session.get('user_id')
    if not uid:
        g.user = None; return
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT role,is_blocked,username FROM users WHERE user_id=%s",(uid,))
    row = cur.fetchone()
    if row:
        session.update({'role':row[0],'is_blocked':row[1],'username':row[2]})
    else:
        session.clear()
    cur.close(); conn.close(); g.user = session.get('username')

#статики для админки 
@app.route('/admin/users')
@admin_required
def admin_users_spa():
    return send_from_directory(app.static_folder, 'admin_users.html')

@app.route('/admin/teams')
@admin_required
def admin_teams_spa():
    return send_from_directory(app.static_folder, 'admin_teams.html')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def spa(path=''):
    if path.startswith('api/'):
        abort(404)
    full = os.path.join(app.static_folder, path)
    if path and os.path.isfile(full):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# ───────────────────── AUTH ─────────────────────
MAX_LOGIN = 32

@app.post('/api/auth/register')
def register():
    d = request.get_json(silent=True) or {}
    u, p, c = d.get('username','').strip(), d.get('password',''), d.get('confirm_password','')
    if p != c:
        return json_error(400, "Пароли не совпадают")
    if not u or len(u) > MAX_LOGIN:
        return json_error(400, f"Длина логина 1-{MAX_LOGIN} символов")
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=%s", (u,))
    if cur.fetchone():
        cur.close(); conn.close()
        return json_error(409, "Такой пользователь уже существует")
    cur.execute("INSERT INTO users(username,password,role) VALUES(%s,%s,'player') RETURNING user_id",
                (u, generate_password_hash(p)))
    session.update({'user_id':cur.fetchone()[0],'username':u,'role':'player'})
    conn.commit(); cur.close(); conn.close()
    return jsonify(ok=True)

@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}
    u,p=d.get('username',''),d.get('password','')
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT user_id,password,role FROM users WHERE username=%s",(u,))
    row=cur.fetchone(); cur.close(); conn.close()
    if not row or not check_password_hash(row[1], p):
        return json_error(401,"Неверный логин или пароль")
    session.update({'user_id':row[0],'username':u,'role':row[2]})
    return jsonify(ok=True)

@app.post('/change_password')
@login_required
def change_password():
    old = request.form.get('old','').strip()
    new = request.form.get('new','').strip()
    if not old or not new:
        return json_error(400, 'Оба поля обязательны')
    conn = get_db_connection(); cur = conn.cursor()
    
    cur.execute("SELECT password FROM users WHERE user_id=%s", (session['user_id'],)) # проверяем текущий хэш
    row = cur.fetchone()
    if not row or not check_password_hash(row[0], old):
        cur.close(); conn.close()
        return json_error(400, 'Неверный пароль')

    hashed = generate_password_hash(new)  # обновляем новый
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed, session['user_id']))
    conn.commit(); cur.close(); conn.close()
    return jsonify(ok=True, msg='Пароль успешно изменён')

@app.post('/api/delete_account')
@login_required
def delete_account():
    d = request.get_json(silent=True) or {}
    pwd = d.get('pwd', '')
    conn = get_db_connection()
    cur = conn.cursor()

    if session.get('role') == 'admin':
        return json_error(403, 'Администратор не может удалить свой аккаунт')
    
    cur.execute("SELECT password FROM users WHERE user_id = %s", (session['user_id'],)) # проверяем, что пароль правильный
    row = cur.fetchone()
    if not row or not check_password_hash(row[0], pwd):
        cur.close(); conn.close()
        return json_error(400, "Неверный пароль")

    cur.execute("DELETE FROM users WHERE user_id = %s", (session['user_id'],)) # удаляем пользователя
    conn.commit()
    cur.close(); conn.close()
    session.clear()
    return jsonify(ok=True)

@app.post('/api/auth/logout')
@login_required
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get('/api/auth/me')
@login_required
def me():
    return jsonify(ok=True, data={
        'user_id'   : session['user_id'],
        'username'  : session['username'],
        'role'      : session['role'],
        'is_blocked': session.get('is_blocked', False)
    })

#Dashboard
@app.get('/api/dashboard')
@login_required
def dashboard():
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("""
        SELECT e.event_id,e.name,e.type,e.description,
               t.team_name,u.username
          FROM events e
          JOIN event_teams et ON et.event_id=e.event_id
          JOIN teams t        ON t.team_id = et.team_id
          JOIN users u        ON u.user_id = e.created_by
         WHERE e.status='finished'
           AND et.points=(SELECT MAX(points) FROM event_teams WHERE event_id=e.event_id)
         GROUP BY e.event_id,t.team_name,u.username
         ORDER BY e.event_id DESC LIMIT 15
    """)
    res=[]
    for r in cur.fetchall():
        cur.execute("""SELECT ROW_NUMBER() OVER(ORDER BY points DESC),
                              t.team_name,et.points
                         FROM event_teams et JOIN teams t USING(team_id)
                        WHERE et.event_id=%s
                        ORDER BY et.points DESC""",(r[0],))
        res.append({'event_id':r[0],'name':r[1],'type':r[2],'description':r[3],
                    'winner':r[4],'host':r[5],'leaderboard':cur.fetchall()})
    cur.close(); conn.close()
    return jsonify(ok=True,data=res)

def current_team():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT t.team_id,
               t.team_name,
               t.invite_code
          FROM teams t
          JOIN team_members tm ON t.team_id = tm.team_id
         WHERE tm.user_id = %s AND tm.active
    """, (session['user_id'],))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None, []

    team = {
        'team_id':    row[0],
        'team_name':  row[1],
        'invite_code':row[2]
    }

    cur.execute("""
        SELECT u.user_id, u.username, u.is_blocked
          FROM users u
          JOIN team_members tm ON tm.user_id = u.user_id
         WHERE tm.team_id = %s AND tm.active
    """, (team['team_id'],))
    members = [
        {'user_id': r[0], 'username': r[1], 'is_blocked': r[2]}
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return team, members

#Команда
@app.get('/api/team')
@login_required
def team_get():
    team,members=current_team()
    if not team:
        return jsonify(ok=True,data=None)
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT e.event_id) FROM events e JOIN event_teams et USING(event_id) WHERE et.team_id=%s AND e.status='finished'",(team['team_id'],))
    total=cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events e WHERE e.status='finished' AND (SELECT MAX(points) FROM event_teams WHERE event_id=e.event_id)=(SELECT points FROM event_teams WHERE event_id=e.event_id AND team_id=%s)",(team['team_id'],))
    wins=cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify(ok=True,data={'team':team,'members':members,'stats':{'total':total,'wins':wins}})

@app.get('/api/team/history')
@login_required
def team_history():
    page=max(int(request.args.get('page',1)),1)
    team,_=current_team()
    if not team:
        return json_error(400,'Нужно состоять в команде')
    off=(page-1)*HIST_PER_PAGE
    conn=get_db_connection(); cur=conn.cursor()

    cur.execute("""SELECT COUNT(*) FROM events e JOIN event_teams et USING(event_id)
                 WHERE et.team_id=%s AND e.status='finished'""",(team['team_id'],))     # сколько всего строк
    total=cur.fetchone()[0]
    pages=(total+HIST_PER_PAGE-1)//HIST_PER_PAGE

    cur.execute("""SELECT e.name, TO_CHAR(NOW()::date,'DD.MM.YYYY') AS dt, et.points,     
                         (SELECT t2.team_name FROM event_teams et2 JOIN teams t2 USING(team_id)
                           WHERE et2.event_id=e.event_id ORDER BY et2.points DESC LIMIT 1)
                  FROM events e JOIN event_teams et USING(event_id)
                 WHERE et.team_id=%s AND e.status='finished'
                 ORDER BY e.event_id DESC LIMIT %s OFFSET %s""",
                (team['team_id'], HIST_PER_PAGE, off)) # сами данные
    hist=[{'name':r[0],'date':r[1],'my_pts':r[2],'winner':r[3]} for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(ok=True,data={'history':hist,'page':page,'pages':pages})

@app.post('/api/team/create')
@login_required
def team_create():
    if session.get('is_blocked'):
        return json_error(403, 'Аккаунт заблокирован')
    
    d = request.get_json(silent=True) or {}
    name = str(d.get('team_name', '')).strip()[:32]
    
    if len(name) < 3:
        return json_error(400, 'Название слишком короткое')
    
    code_raw = str(d.get('invite_code', '')).strip()[:16]
    
    code = code_raw if code_raw else None
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute('INSERT INTO teams(team_name, invite_code) VALUES(%s, %s) RETURNING team_id', (name, code))
        tid = cur.fetchone()[0]
        
        cur.execute("""INSERT INTO team_members(user_id, team_id, active) 
                       VALUES(%s, %s, TRUE) 
                       ON CONFLICT (user_id) DO UPDATE SET team_id = EXCLUDED.team_id, active = TRUE""",
                    (session['user_id'], tid))
        
        conn.commit()
    except UniqueViolation as e:
        conn.rollback()
        if 'teams_name_unique' in e.pgerror:
            return json_error(409, 'Имя команды уже занято')
        if 'teams_code_unique' in e.pgerror:
            return json_error(409, 'Код команды уже занят')
        return json_error(409, 'Команда с такими данными уже существует')
    finally:
        cur.close()
        conn.close()
    
    return jsonify(ok=True)

@app.post('/api/team/join')
@login_required
def team_join():
    if session.get('is_blocked'):
        return json_error(403,'Аккаунт заблокирован')
    d=request.get_json(silent=True) or {}
    code=str(d.get('invite_code','')).strip()[:16]
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute('SELECT team_id FROM teams WHERE invite_code=%s',(code,))
    row=cur.fetchone()
    if not row:
        cur.close(); conn.close(); return json_error(404,'Неверный код')
    tid=row[0]
    cur.execute("""INSERT INTO team_members(user_id,team_id,active) VALUES(%s,%s,TRUE)
                 ON CONFLICT (user_id) DO UPDATE SET team_id=EXCLUDED.team_id,active=TRUE""",
                (session['user_id'],tid))
    conn.commit(); cur.close(); conn.close();
    return jsonify(ok=True)

@app.post('/api/team/leave')
@login_required
def team_leave():
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute('DELETE FROM team_members WHERE user_id=%s',(session['user_id'],))
    if cur.rowcount: conn.commit()
    cur.close(); conn.close();
    return jsonify(ok=True)

@app.get("/api/events")
@login_required
def events_get():
    team, _ = current_team()
    if not team:
        return jsonify(ok=True, data={"team": None})

    conn = get_db_connection(); cur = conn.cursor()

    #waiting / running / finished
    cur.execute("""
        SELECT e.event_id,e.name,e.status,e.type,e.description,e.file_path
          FROM events e
          JOIN event_teams et USING(event_id)
         WHERE et.team_id = %s
           AND e.status IN ('waiting','running','finished')
         ORDER BY e.event_id DESC
         LIMIT 1
    """, (team['team_id'],))
    cur_ev = cur.fetchone()

    leaderboard = []
    if cur_ev and cur_ev[2] in ('running','finished'):
        cur.execute("""
            SELECT ROW_NUMBER() OVER(ORDER BY et.points DESC),
                   t.team_name, et.points
              FROM event_teams et JOIN teams t USING(team_id)
             WHERE et.event_id = %s
             ORDER BY et.points DESC
        """, (cur_ev[0],))
        leaderboard = cur.fetchall()

    cur.execute("""
        SELECT e.event_id,e.name,e.type,e.description,
               (SELECT COUNT(*) FROM event_teams et WHERE et.event_id=e.event_id) AS teams_cnt
          FROM events e
         WHERE e.status='waiting'
           AND NOT EXISTS (
                 SELECT 1 FROM event_teams
                  WHERE event_id=e.event_id AND team_id=%s)
         ORDER BY e.event_id DESC
    """, (team['team_id'],)) #без waiting 
    waiting = cur.fetchall()
    cur.close(); conn.close()

    return jsonify(ok=True, data={
        "team": team,
        "current_event": cur_ev,
        "leaderboard": leaderboard,
        "waiting": waiting,
    })

@app.post('/api/events/join')
@login_required
def events_join():
    team, members = current_team()    #команда и её участники
    if not team:
        return json_error(400, "Нужно состоять в команде")

    if any(m['is_blocked'] for m in members): #если хоть один участник заблокирован
        return json_error(403, "Один из участников команды заблокирован администратором")

    data = request.get_json(silent=True) or {}
    code = str(data.get('code')) if 'code' in data else None
    eid  = data.get('event_id')
    conn = get_db_connection(); cur = conn.cursor()

    if code:
        cur.execute("SELECT event_id,status FROM events WHERE code=%s", (code[:16],))
        ev = cur.fetchone()
        if not ev:
            cur.close(); conn.close(); return json_error(404, "Код не найден")
        if ev[1] != "waiting":
            cur.close(); conn.close(); return json_error(400, "Регистрация закрыта")
        eid = ev[0]

    try:
        cur.execute(
            "INSERT INTO event_teams(event_id,team_id) VALUES(%s,%s)",
            (eid, team["team_id"]),
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
    finally:
        cur.close(); conn.close()

    return jsonify(ok=True)

@app.post("/api/events/leave")
@login_required
def events_leave():
    team, _ = current_team()
    if not team:
        return json_error(400, "Нужно состоять в команде")

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        DELETE FROM event_teams
         WHERE team_id = %s
           AND event_id IN (
               SELECT event_id FROM events
                WHERE status IN ('waiting','running')
           )
    """, (team['team_id'],))
    conn.commit()
    cur.close(); conn.close()
    return jsonify(ok=True)

@app.post("/api/events/submit/<int:eid>")
@login_required
def submit_answer(eid):
    team, _ = current_team()
    if not team:
        return json_error(400, "Нужно состоять в команде")
    data = request.get_json(silent=True) or {}
    ans = str(data.get("answer", "")).strip()
    if not ans:
        return json_error(400, "Пустой ответ")

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT answer,status FROM events WHERE event_id=%s", (eid,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close(); return json_error(404, "Событие не найдено")
    correct, status = row
    if status != "running":
        cur.close(); conn.close(); return json_error(400, "Приём ответов закрыт")
    cur.execute(
        "INSERT INTO event_submits(event_id,team_id,user_id,answer) VALUES(%s,%s,%s,%s)",
        (eid, team["team_id"], session["user_id"], ans),
    )
    if ans.lower() == correct.lower():
        cur.execute(
            "UPDATE event_teams SET points=points+1 WHERE event_id=%s AND team_id=%s",
            (eid, team["team_id"]),
        )
    conn.commit(); cur.close(); conn.close()
    return jsonify(ok=True)

# модерка
@app.route('/api/mod/events', methods=['POST'])
@moderator_required
def mod_create():
    code    = (request.form.get('code') or '').strip()[:16]
    name    = request.form.get('name','').strip()[:64]
    desc    = request.form.get('desc','').strip()
    ev_type = request.form.get('ev_type','').strip()
    answer  = request.form.get('answer','').strip()
    pdf     = request.files.get('task')

    if not code: # все поля обязательны
        return json_error(400, 'Код события обязателен')
    if not name or not desc or not ev_type or not answer:
        return json_error(400, 'Все поля должны быть заполнены')
    if not pdf or not pdf.filename.lower().endswith('.pdf'):
        return json_error(400, 'Нужен файл в формате PDF')

    filename = secure_filename(pdf.filename)
    rel_path = os.path.join('tasks', filename)
    abs_path = os.path.join(app.static_folder, rel_path)
    pdf.save(abs_path)

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO events(code,name,description,type,answer,file_path,created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING code,name
        """, (code, name, desc, ev_type, answer, rel_path, session['user_id']))
        code_ret, name_ret = cur.fetchone()
        conn.commit()
    except UniqueViolation as e:
        conn.rollback()
        if 'events_code_unique' in e.pgerror:
            return json_error(409, 'Код события уже занят')
        if 'events_name_unique' in e.pgerror:
            return json_error(409, 'Название события уже занято')
        return json_error(409, 'Событие с такими данными уже существует')
    finally:
        cur.close(); conn.close()

    return jsonify(ok=True, data={'code': code_ret, 'name': name_ret})

@app.route('/api/mod/events', methods=['GET'])
@moderator_required
def mod_active():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT e.code,e.name,e.type,e.status,
                          (SELECT COUNT(*) FROM event_teams et WHERE et.event_id=e.event_id) AS teams,
                          e.description
                     FROM events e
                    WHERE e.status IN ('waiting','running')
                    ORDER BY e.event_id DESC""")
    data = [{
        'code': r[0], 'name': r[1], 'type': r[2],
        'status': r[3], 'teams': r[4], 'description': r[5]
    } for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(ok=True, data=data)

@app.route('/api/mod/events/<code>', methods=['GET'])
@moderator_required
def mod_manage_get(code):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT event_id,name,status FROM events WHERE code=%s", (code,))
    ev = cur.fetchone()
    if not ev:
        cur.close(); conn.close()
        return json_error(404, "Событие не найдено")
    eid,name,status = ev

    cur.execute("""
        SELECT et.team_id, t.team_name, et.points,
               COALESCE(ls.answer,'') AS last_ans,
               COALESCE(TO_CHAR(ls.ts,'HH24:MI:SS'),'—') AS last_ts
          FROM event_teams et
          JOIN teams t USING(team_id)
          LEFT JOIN LATERAL (
                SELECT answer, ts FROM event_submits s
                 WHERE s.team_id=et.team_id AND s.event_id=et.event_id
                 ORDER BY ts DESC LIMIT 1
          ) ls ON TRUE
         WHERE et.event_id=%s
         ORDER BY et.id
    """, (eid,))
    teams = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(ok=True, data={'event': ev, 'teams': teams})

@app.route('/api/mod/events/<code>', methods=['PATCH'])
@moderator_required
def mod_manage_patch(code):
    data = request.get_json(silent=True) or {}
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT event_id,status FROM events WHERE code=%s", (code,))
    ev = cur.fetchone()
    if not ev:
        cur.close(); conn.close()
        return json_error(404, "Событие не найдено")
    eid,status = ev

    if data.get('start') and status=='waiting':
        cur.execute("UPDATE events SET status='running' WHERE event_id=%s", (eid,))
    elif data.get('finish') and status!='finished':
        cur.execute("UPDATE events SET status='finished' WHERE event_id=%s", (eid,))
    elif 'delta' in data and status!='finished':
        delta = int(data['delta']); tid = int(data['team_id'])
        cur.execute("UPDATE event_teams SET points=GREATEST(points+%s,0) WHERE event_id=%s AND team_id=%s",
                    (delta, eid, tid))
    elif data.get('dq') and status!='finished':
        tid = int(data['team_id'])
        cur.execute("DELETE FROM event_teams WHERE event_id=%s AND team_id=%s", (eid, tid))
    else:
        cur.close(); conn.close()
        return json_error(400, "Неверная операция")

    conn.commit(); cur.close(); conn.close()
    return jsonify(ok=True)

#адмика
@app.get('/api/admin/users')
@admin_required
def admin_users():
    page  = max(int(request.args.get('page', 1)), 1)
    q     = request.args.get('q', '').strip()
    sort  = request.args.get('sort', 'user_id')
    order = request.args.get('dir',  'asc')

    if sort not in {'user_id','username','role','is_blocked'}:
        sort = 'user_id'
    dir_sql = 'ASC' if order=='asc' else 'DESC'

    base_from = "FROM users u"
    where, params = '', []

    if q:
        where = """
          WHERE CAST(u.user_id AS TEXT) ILIKE %s
             OR u.username ILIKE %s
             OR EXISTS (
                 SELECT 1 FROM team_members tm2
                  WHERE tm2.user_id = u.user_id
                    AND CAST(tm2.team_id AS TEXT) ILIKE %s
             )
        """
        params = [f'%{q}%', f'%{q}%', f'%{q}%']

    sql_count = f"SELECT COUNT(*) {base_from} {where}"

    sql_rows = f"""
        SELECT u.user_id,
               u.username,
               COALESCE(l.team,'—') AS team,
               u.role,
               u.is_blocked
          FROM users u
          LEFT JOIN LATERAL (
            SELECT t.team_name||' ('||t.team_id||')' AS team
              FROM team_members tm
              JOIN teams t USING(team_id)
             WHERE tm.user_id = u.user_id AND tm.active
             LIMIT 1
          ) l ON TRUE
         {where}
         ORDER BY {sort} {dir_sql}, u.user_id
         LIMIT %s OFFSET %s
    """

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(sql_count, params)
    total = cur.fetchone()[0]
    cur.execute(sql_rows, params + [PER_PAGE, (page-1)*PER_PAGE])
    users = [list(r) for r in cur.fetchall()]
    cur.close(); conn.close()

    pages = (total + PER_PAGE - 1)//PER_PAGE
    return jsonify(ok=True, data={'users':users,'page':page,'pages':pages})

@app.post('/api/admin/user_action')
@admin_required
def admin_user_action():
    d = request.get_json(silent=True) or {}
    uid, act = d.get('uid'), d.get('act')

    if uid == session.get('user_id') and act == 'moder':

        return json_error(403, 'Невозможно изменить роль для самого себя') 

    if not uid or act not in {'delete', 'moder', 'toggle'}:

        return json_error(400, 'Некорректные параметры')


    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if act == 'delete':
            cur.execute("DELETE FROM users WHERE user_id=%s", (uid,))
            if str(uid) == str(session.get('user_id')):
                session.clear()
        elif act == 'moder':
            cur.execute("UPDATE users SET role='moderator' WHERE user_id=%s", (uid,))
        elif act == 'toggle':
            cur.execute("UPDATE users SET is_blocked=NOT is_blocked WHERE user_id=%s", (uid,))

        conn.commit()
    except Exception as e:
        conn.rollback()
        return json_error(500, f"Ошибка выполнения операции: {str(e)}")
    finally:
        cur.close()
        conn.close()

    return jsonify(ok=True) 

@app.get('/api/admin/teams')
@admin_required
def admin_teams():
    page  = max(int(request.args.get('page', 1)), 1)
    q     = request.args.get('q', '').strip()
    sort  = request.args.get('sort', 'team_id')
    order = request.args.get('dir',  'asc')
    if sort not in {'team_id','team_name','members'}:
        sort = 'team_id'
    dir_sql = 'ASC' if order == 'asc' else 'DESC'

    base_from = "FROM teams t"
    where, params = '', []
    if q:
        where = """
          WHERE CAST(t.team_id AS TEXT) ILIKE %s
             OR t.team_name ILIKE %s
             OR EXISTS (
                 SELECT 1 FROM team_members tm2
                  WHERE tm2.team_id = t.team_id
                    AND CAST(tm2.user_id AS TEXT) ILIKE %s
             )
        """
        params = [f'%{q}%', f'%{q}%', f'%{q}%']

    sql_count = f"SELECT COUNT(DISTINCT t.team_id) {base_from} {where}"

    sql_rows = f"""
        SELECT t.team_id,
               t.team_name,
               COALESCE(m.member_ids,'') AS member_ids,
               COALESCE(m.members,0)    AS members
          FROM teams t
          LEFT JOIN LATERAL (
            SELECT string_agg(tm.user_id::TEXT, ', ') AS member_ids,
                   COUNT(*)                           AS members
              FROM team_members tm
             WHERE tm.team_id = t.team_id
          ) m ON TRUE
         {where}
         ORDER BY {sort} {dir_sql}
         LIMIT %s OFFSET %s
    """

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(sql_count, params)
    total = cur.fetchone()[0]
    cur.execute(sql_rows, params + [PER_PAGE, (page-1)*PER_PAGE])
    teams = [list(r) for r in cur.fetchall()]
    cur.close(); conn.close()

    pages = (total + PER_PAGE - 1)//PER_PAGE
    return jsonify(ok=True, data={'teams':teams,'page':page,'pages':pages})

@app.post('/api/admin/team_action')
@admin_required
def admin_team_action():
    d=request.get_json(silent=True) or {}
    tid, act = d.get('tid'), d.get('act')
    if not tid or act not in {'delete','disband','kick'}:
        return json_error(400,'bad params')

    conn=get_db_connection(); cur=conn.cursor()
    if act=='delete':
        cur.execute("DELETE FROM teams WHERE team_id=%s",(tid,))
    elif act=='disband':
        cur.execute("DELETE FROM team_members WHERE team_id=%s",(tid,))
    elif act=='kick':
        uid=d.get('kick_uid')
        if not uid: cur.close(); conn.close(); return json_error(400,'kick_uid?')
        cur.execute("DELETE FROM team_members WHERE team_id=%s AND user_id=%s",(tid,uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify(ok=True)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
