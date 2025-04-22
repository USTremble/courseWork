from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2, psycopg2.errors

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
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        u, p, c = request.form['username'], request.form['password'], request.form['confirm_password']
        if p != c:
            error = 'Пароли не совпадают'
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

@app.route('/events')
@login_required
def events():
    return render_template('events.html', page_title='События')

# ───────── профиль ─────────────────────────────────────────
EVENTS_PER_PAGE=10
def user_stats(uid):
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT COUNT(*), SUM(is_winner::int) FROM event_participants WHERE user_id=%s",(uid,))
    total,wins=cur.fetchone(); cur.close(); conn.close()
    return {'total':total or 0,'wins':wins or 0}

@app.route('/profile')
@login_required
def profile():
    uid=session['user_id']; page=max(int(request.args.get('page',1)),1); off=(page-1)*EVENTS_PER_PAGE
    stats=user_stats(uid)

    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT is_blocked FROM users WHERE user_id=%s",(uid,)); is_blocked=cur.fetchone()[0]

    cur.execute("""
        SELECT e.date,e.name,mt.team_name,wt.team_name
        FROM events e
        JOIN event_participants ep ON ep.event_id=e.event_id
        JOIN teams mt ON mt.team_id=ep.team_id
        JOIN teams wt ON wt.team_id=e.winner_team_id
        WHERE ep.user_id=%s
        ORDER BY e.date DESC LIMIT %s OFFSET %s
    """,(uid,EVENTS_PER_PAGE,off))
    history=[{'date':r[0],'name':r[1],'my_team':r[2],'winner':r[3]} for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM event_participants WHERE user_id=%s",(uid,))
    total=cur.fetchone()[0]; pages=(total+EVENTS_PER_PAGE-1)//EVENTS_PER_PAGE
    cur.close(); conn.close()

    return render_template('profile.html', page_title='Профиль',
                           stats=stats,is_blocked=is_blocked,
                           history=history,page=page,pages=pages,
                           pass_msg=request.args.get('pm'),
                           pass_ok=request.args.get('ok')=='1')

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
    name,desc,code=request.form['team_name'],request.form['description'],request.form['invite_code']
    conn=get_db_connection(); cur=conn.cursor()
    try:
        cur.execute("INSERT INTO teams (team_name,description,invite_code) VALUES (%s,%s,%s) RETURNING team_id",
                    (name,desc,code))
        tid=cur.fetchone()[0]
        cur.execute("INSERT INTO team_members (team_id,user_id) VALUES (%s,%s)",(tid,session['user_id']))
        conn.commit(); flash('Команда создана')
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); flash('Имя или код уже заняты','error')
    finally:
        cur.close(); conn.close()
    return redirect(url_for('team'))

@app.route('/join_team', methods=['POST'])
@login_required
def join_team():
    code=request.form['invite_code']
    conn=get_db_connection(); cur=conn.cursor()
    cur.execute("SELECT team_id FROM teams WHERE invite_code=%s",(code,))
    row=cur.fetchone()
    if row:
        cur.execute("INSERT INTO team_members (team_id,user_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",(row[0],session['user_id']))
        conn.commit(); flash('Вы присоединились к команде')
    else:
        flash('Неверный код','error')
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
        uid=request.form.get('uid')
        if uid: cur.execute("DELETE FROM team_members WHERE team_id=%s AND user_id=%s",(tid,uid))
    conn.commit(); cur.close(); conn.close()
    return redirect(request.referrer or url_for('admin_teams'))

# ───────── index ────────────────────────────────────────
@app.route('/')
def index(): return redirect(url_for('dashboard')) if g.user else render_template('index.html')

if __name__=='__main__': app.run(debug=True)
