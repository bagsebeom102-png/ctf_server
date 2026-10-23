import os
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory,
    make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
MAIN_DB = BASE_DIR / "ctf.db"
SQLI_DB = BASE_DIR / "challenge_sqli.db"
CHALLENGE_DIR = BASE_DIR / "challenge_files"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-please")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")


PROBLEMS = [
    {
        "id": 1,
        "category": "system",
        "title": "권한 상승 - sudo 설정 분석",
        "points": 100,
        "description": """
가상의 Linux 서버에서 `sudo -l`을 실행했더니 다음과 같이 표시되었습니다.

User student may run the following commands on dh-ctf:
    (root) NOPASSWD: /usr/bin/cat /opt/ctf/root_flag.txt

관리자 권한으로 허용된 명령을 이용해 `/opt/ctf/root_flag.txt`를 읽는다고 가정하세요.
""",
        "flag": "DH{sudo_cat_privilege}",
        "file": "system1_terminal.txt",
    },
    {
        "id": 2,
        "category": "system",
        "title": "파일 권한 - 잘못된 권한 찾기",
        "points": 100,
        "description": """
가상 서버의 파일 목록을 조사하여 다른 사용자가 읽을 수 있도록 잘못 설정된 flag 파일을 찾으세요.
`ls -l` 결과를 보고 어떤 파일을 읽어야 하는지 판단하면 됩니다.
""",
        "flag": "DH{file_permission_mistake}",
        "file": "system2_permissions.txt",
    },
    {
        "id": 3,
        "category": "reversing",
        "title": "리버싱 - 문자열은 어디에?",
        "points": 100,
        "description": """
제공된 파일을 메모장 또는 문자열 확인 도구로 열어 보세요.
프로그램 안에 개발자가 실수로 남긴 문자열이 있습니다.
""",
        "flag": "DH{strings_are_visible}",
        "file": "rev1.bin",
    },
    {
        "id": 4,
        "category": "reversing",
        "title": "리버싱 - 간단한 연산",
        "points": 120,
        "description": """
제공된 Python 코드를 분석해 최종 check 값을 계산하세요.
정답 형식은 DH{숫자} 입니다.
""",
        "flag": "DH{173}",
        "file": "rev2.py",
    },
    {
        "id": 5,
        "category": "web",
        "title": "웹 해킹 - Cookie",
        "points": 120,
        "description": """
아래 '문제 열기'를 눌러 Cookie Challenge로 이동하세요.
브라우저 개발자 도구에서 `role` 쿠키를 확인해 보세요.
관리자가 되면 flag가 표시됩니다.
""",
        "flag": "DH{cookie_role_admin}",
        "route": "cookie_challenge",
    },
    {
        "id": 6,
        "category": "web",
        "title": "웹 해킹 - SQL Injection 기초",
        "points": 150,
        "description": """
아래 '문제 열기'에서 로그인 우회 SQL Injection을 시도하세요.
이 문제는 메인 회원 DB와 완전히 분리된 연습용 SQLite DB만 사용합니다.
""",
        "flag": "DH{basic_sql_injection}",
        "route": "sqli_challenge",
    },
    {
        "id": 7,
        "category": "crypto",
        "title": "암호학 - ROT28",
        "points": 100,
        "description": """
알파벳은 26글자입니다. 따라서 ROT28은 ROT2와 같은 효과를 냅니다.

암호문:
FJ{tqv28_ku_gcua}

이를 복호화하세요.
""",
        "flag": "DH{rot28_is_easy}",
    },
    {
        "id": 8,
        "category": "crypto",
        "title": "암호학 - XOR",
        "points": 130,
        "description": """
아래 16진수 바이트들은 각 문자를 키 0x17과 XOR한 결과입니다.

53 5F 6C 6F 78 65 48 75 76 64 7E 74 6A

각 바이트에 다시 0x17을 XOR하여 평문을 복구하세요.
""",
        "flag": "DH{xor_basic}",
    },
]

CATEGORY_NAMES = {
    "system": "시스템 해킹",
    "reversing": "리버싱",
    "web": "웹 해킹",
    "crypto": "암호학",
}


def get_db():
    conn = sqlite3.connect(MAIN_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_main_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS solves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            problem_id INTEGER NOT NULL,
            solved_at TEXT NOT NULL,
            UNIQUE(user_id, problem_id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    admin = cur.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        cur.execute(
            "INSERT INTO users(username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)",
            ("admin", generate_password_hash(ADMIN_PASSWORD), datetime.now().isoformat(timespec="seconds"))
        )
    conn.commit()
    conn.close()


def init_sqli_db():
    conn = sqlite3.connect(SQLI_DB)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS challenge_users")
    cur.execute("""
        CREATE TABLE challenge_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            flag TEXT
        )
    """)
    cur.execute(
        "INSERT INTO challenge_users(username, password, role, flag) VALUES (?, ?, ?, ?)",
        ("admin", "not_the_real_password", "admin", "DH{basic_sql_injection}")
    )
    cur.execute(
        "INSERT INTO challenge_users(username, password, role, flag) VALUES (?, ?, ?, ?)",
        ("guest", "guest", "user", None)
    )
    conn.commit()
    conn.close()


def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "category_names": CATEGORY_NAMES
    }


@app.route("/")
def index():
    if "user_id" in session:
        user = current_user()
        if user and user["is_admin"]:
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 20:
            flash("아이디는 3~20자로 입력하세요.", "error")
            return redirect(url_for("register"))
        if not username.replace("_", "").isalnum():
            flash("아이디는 영문/숫자/밑줄만 사용할 수 있습니다.", "error")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("비밀번호는 6자 이상으로 입력하세요.", "error")
            return redirect(url_for("register"))
        if username.lower() == "admin":
            flash("admin 아이디는 사용할 수 없습니다.", "error")
            return redirect(url_for("register"))

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                (username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds"))
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("이미 존재하는 아이디입니다.", "error")
            return redirect(url_for("register"))
        conn.close()

        flash("회원가입이 완료되었습니다. 로그인하세요.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]

        if user["is_admin"]:
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    conn = get_db()
    solved_rows = conn.execute(
        "SELECT problem_id FROM solves WHERE user_id = ?", (user["id"],)
    ).fetchall()
    conn.close()
    solved = {row["problem_id"] for row in solved_rows}

    grouped = {}
    for key in CATEGORY_NAMES:
        grouped[key] = [p for p in PROBLEMS if p["category"] == key]

    return render_template("dashboard.html", grouped=grouped, solved=solved)


@app.route("/problem/<int:problem_id>")
def problem(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    p = next((x for x in PROBLEMS if x["id"] == problem_id), None)
    if not p:
        return "문제를 찾을 수 없습니다.", 404

    conn = get_db()
    solved = conn.execute(
        "SELECT 1 FROM solves WHERE user_id = ? AND problem_id = ?",
        (user["id"], problem_id)
    ).fetchone() is not None
    conn.close()

    return render_template("problem.html", p=p, solved=solved)


@app.route("/system-terminal/<int:problem_id>")
def system_terminal(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    p = next((x for x in PROBLEMS if x["id"] == problem_id and x["category"] == "system"), None)
    if not p:
        return "시스템 해킹 문제를 찾을 수 없습니다.", 404
    return render_template("system_terminal.html", problem_id=problem_id)


@app.route("/submit/<int:problem_id>", methods=["POST"])
def submit(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    p = next((x for x in PROBLEMS if x["id"] == problem_id), None)
    if not p:
        return "문제를 찾을 수 없습니다.", 404

    answer = request.form.get("flag", "").strip()

    # 일반 문자열 비교 대신 digest 비교
    ok = hashlib.sha256(answer.encode()).digest() == hashlib.sha256(p["flag"].encode()).digest()

    if ok:
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO solves(user_id, problem_id, solved_at) VALUES (?, ?, ?)",
            (user["id"], problem_id, datetime.now().isoformat(timespec="seconds"))
        )
        conn.commit()
        conn.close()
        flash("정답입니다! 🎉", "success")
    else:
        flash("틀렸습니다.", "error")

    return redirect(url_for("problem", problem_id=problem_id))


@app.route("/challenge-file/<path:filename>")
def challenge_file(filename):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    allowed = {p.get("file") for p in PROBLEMS if p.get("file")}
    if filename not in allowed:
        return "허용되지 않은 파일입니다.", 403

    return send_from_directory(CHALLENGE_DIR, filename, as_attachment=True)


@app.route("/cookie-challenge")
def cookie_challenge():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    role = request.cookies.get("role", "user")
    flag = "DH{cookie_role_admin}" if role == "admin" else None

    response = make_response(render_template("cookie_challenge.html", role=role, flag=flag))
    if "role" not in request.cookies:
        response.set_cookie("role", "user", httponly=False, samesite="Lax")
    return response


@app.route("/sqli-challenge", methods=["GET", "POST"])
def sqli_challenge():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    result = None
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 의도적으로 취약한 CTF 전용 쿼리입니다.
        # 메인 회원 DB가 아닌 challenge_sqli.db에만 연결합니다.
        query = (
            "SELECT username, role, flag FROM challenge_users "
            f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
        )

        conn = sqlite3.connect(SQLI_DB)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(query).fetchone()
            if row:
                if row["role"] == "admin":
                    result = row["flag"]
                else:
                    result = "로그인은 성공했지만 admin 계정이 아닙니다."
            else:
                result = "로그인 실패"
        except sqlite3.Error:
            error = "SQL 문법 오류가 발생했습니다."
        finally:
            conn.close()

    return render_template("sqli_challenge.html", result=result, error=error)


@app.route("/admin")
def admin():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not user["is_admin"]:
        return "관리자만 접근할 수 있습니다.", 403

    conn = get_db()
    users = conn.execute(
        "SELECT id, username, created_at FROM users WHERE is_admin = 0 ORDER BY id ASC"
    ).fetchall()

    solve_rows = conn.execute("""
        SELECT s.user_id, s.problem_id, s.solved_at
        FROM solves s
        ORDER BY s.solved_at ASC
    """).fetchall()
    conn.close()

    solve_map = {}
    for row in solve_rows:
        solve_map[(row["user_id"], row["problem_id"])] = row["solved_at"]

    return render_template(
        "admin.html",
        users=users,
        problems=PROBLEMS,
        solve_map=solve_map
    )


if __name__ == "__main__":
    init_main_db()
    init_sqli_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
