import os
import re
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory,
    make_response, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
MAIN_DB = BASE_DIR / "ctf.db"
SQLI_DB = BASE_DIR / "challenge_sqli.db"
CHALLENGE_DIR = BASE_DIR / "challenge_files"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-please")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")
SITE_PASSWORD = os.environ.get("SITE_PASSWORD", "dhctf2026")


PROBLEMS = [
    {
        "id": 1,
        "category": "system",
        "title": "권한 상승 - sudo 설정 분석",
        "points": 100,
        "description": """
가상의 Linux 터미널을 분석하는 문제입니다.

문제 파일을 다운로드한 뒤, 아래에 표시되는 것과 같은 터미널 명령어를 직접 입력하며 파일과 권한을 조사하세요.
목표는 `/opt/ctf/root_flag.txt`의 내용을 확인하는 것입니다.

※ 실제 서버의 명령을 실행하는 것이 아니라 CTF용 가상 터미널입니다.
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
가상의 Linux 터미널에서 파일 권한을 조사하세요.
`ls -l`, `cat`, `find` 등의 기본 명령어를 이용해 flag 파일을 찾아 내용을 확인하는 문제입니다.

※ 실제 서버 명령을 실행하는 것이 아니라 CTF용 가상 터미널입니다.
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
        "flag": "DH{258}",
        "file": "rev2.py",
    },
    {
        "id": 5,
        "category": "web",
        "title": "웹 해킹 - Cookie",
        "points": 120,
        "description": """
Cookie Challenge에서 인증 상태를 조작해 관리자 권한을 얻어 flag를 확인하세요.
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
    # 기존 DB에도 IP 컬럼이 자동으로 추가되도록 간단한 마이그레이션을 수행합니다.
    user_columns = [row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()]
    if "ip_address" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN ip_address TEXT")

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


@app.before_request
def site_gate():
    # 사이트 접속 비밀번호는 CTF 로그인과 별개입니다.
    # 한 번 통과하면 로그아웃해도 다시 묻지 않습니다.
    if request.endpoint in {"site_access", "static"}:
        return None
    if not session.get("site_access"):
        return redirect(url_for("site_access"))
    return None

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/site-access", methods=["GET", "POST"])
def site_access():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == SITE_PASSWORD:
            session["site_access"] = True
            return redirect(url_for("index"))
        flash("사이트 비밀번호가 올바르지 않습니다.", "error")
    return render_template("site_access.html")


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
                "INSERT INTO users(username, password_hash, is_admin, created_at, ip_address) VALUES (?, ?, 0, ?, ?)",
                (username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds"), request.remote_addr or "unknown")
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
    site_access = session.get("site_access")
    session.clear()
    if site_access:
        session["site_access"] = True
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["is_admin"]:
        return redirect(url_for("admin"))

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
    if not user or user["is_admin"]:
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


@app.route("/submit/<int:problem_id>", methods=["POST"])
def submit(problem_id):
    user = current_user()
    if not user or user["is_admin"]:
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


@app.route("/system-terminal/<int:problem_id>")
@login_required
def system_terminal(problem_id):
    if problem_id not in (1, 2):
        flash("잘못된 문제입니다.", "error")
        return redirect(url_for("index"))
    return render_template("system_terminal.html", problem_id=problem_id, cwd="/home/ctf")


@app.route("/system-terminal/<int:problem_id>/command", methods=["POST"])
@login_required
def system_terminal_command(problem_id):
    """Educational virtual terminal. Never executes commands on the host OS."""
    if problem_id not in (1, 2):
        return jsonify(output="잘못된 문제입니다.", cwd="/home/ctf"), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}

    command = str(data.get("command") or "").strip()
    cwd = str(data.get("cwd") or "/home/ctf")

    def norm(path, base="/home/ctf"):
        if not path:
            return base
        raw = path if path.startswith("/") else base.rstrip("/") + "/" + path
        parts = []
        for part in raw.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts) if parts else "/"

    # Each request reconstructs the same virtual filesystem; only the returned
    # cwd changes on the client. No host filesystem is touched.
    fs = {
        "/": {"type": "dir", "mode": 0o755},
        "/home": {"type": "dir", "mode": 0o755},
        "/home/ctf": {"type": "dir", "mode": 0o755},
        "/home/ctf/readme.txt": {
            "type": "file", "mode": 0o644, "content": "DH CTF virtual terminal\n"
        },
        "/opt": {"type": "dir", "mode": 0o755},
        "/opt/ctf": {"type": "dir", "mode": 0o755},
        "/opt/ctf/root_flag.txt": {
            "type": "file",
            "mode": 0o400 if problem_id == 1 else 0o000,
            "content": "DH{sudo_cat_privilege}" if problem_id == 1 else "DH{file_permission_mistake}"
        },
    }

    cwd = norm(cwd)
    if cwd not in fs or fs[cwd]["type"] != "dir":
        cwd = "/home/ctf"

    def child_names(directory):
        prefix = directory.rstrip("/") + "/"
        result = []
        for path in fs:
            if path.startswith(prefix):
                rest = path[len(prefix):]
                if rest and "/" not in rest:
                    result.append(rest)
        return sorted(result)

    def mode_string(node):
        m = node["mode"]
        return ("d" if node["type"] == "dir" else "-") + "".join([
            "r" if m & 0o400 else "-", "w" if m & 0o200 else "-", "x" if m & 0o100 else "-",
            "r" if m & 0o040 else "-", "w" if m & 0o020 else "-", "x" if m & 0o010 else "-",
            "r" if m & 0o004 else "-", "w" if m & 0o002 else "-", "x" if m & 0o001 else "-"
        ])

    def solve():
        # Detect the actual schema used by this project and insert safely.
        conn = get_db()
        try:
            cols = [row[1] for row in conn.execute("PRAGMA table_info(solves)").fetchall()]
            if {"user_id", "problem_id"}.issubset(cols):
                if "solved_at" in cols:
                    conn.execute(
                        "INSERT OR IGNORE INTO solves (user_id, problem_id, solved_at) VALUES (?, ?, datetime('now'))",
                        (session["user_id"], problem_id)
                    )
                else:
                    conn.execute(
                        "INSERT OR IGNORE INTO solves (user_id, problem_id) VALUES (?, ?)",
                        (session["user_id"], problem_id)
                    )
                conn.commit()
        finally:
            conn.close()

    if not command:
        return jsonify(output="", cwd=cwd)

    parts = command.split()
    sudo = False
    if parts and parts[0] == "sudo":
        sudo = True
        parts = parts[1:]
    if not parts:
        return jsonify(output="usage: sudo <command>", cwd=cwd)

    cmd, args = parts[0], parts[1:]
    output = ""

    if cmd == "help":
        output = "지원 명령어: pwd, ls, ls -l, cd, cat, chmod, sudo -l, whoami, id, find, clear, help"
    elif cmd == "clear":
        output = ""
    elif cmd == "pwd":
        output = cwd
    elif cmd == "whoami":
        output = "ctf"
    elif cmd == "id":
        output = "uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)"
    elif cmd == "sudo" and args == ["-l"]:
        output = "(root) NOPASSWD: /bin/cat" if problem_id == 1 else "Sorry, user ctf may not run sudo on dh-ctf."
    elif cmd == "cd":
        target = norm(args[0] if args else "/home/ctf", cwd)
        if target not in fs or fs[target]["type"] != "dir":
            output = f"cd: {args[0] if args else '/home/ctf'}: No such file or directory"
        else:
            cwd = target
    elif cmd == "ls":
        long_mode = "-l" in args
        target_arg = next((a for a in args if not a.startswith("-")), None)
        target = norm(target_arg, cwd) if target_arg else cwd
        if target not in fs:
            output = f"ls: cannot access '{target_arg or target}': No such file or directory"
        elif fs[target]["type"] == "file":
            output = mode_string(fs[target]) + " 1 ctf ctf " + target.rsplit("/", 1)[-1] if long_mode else target.rsplit("/", 1)[-1]
        elif long_mode:
            output = "\n".join(
                f"{mode_string(fs[norm(name, target)])} 1 ctf ctf {name}"
                for name in child_names(target)
            )
        else:
            output = "  ".join(child_names(target))
    elif cmd == "cat":
        if not args:
            output = "cat: missing operand"
        else:
            target = norm(args[0], cwd)
            if target not in fs:
                output = f"cat: {args[0]}: No such file or directory"
            elif fs[target]["type"] != "file":
                output = f"cat: {args[0]}: Is a directory"
            elif target == "/opt/ctf/root_flag.txt" and not sudo and not (fs[target]["mode"] & 0o004):
                output = f"cat: {args[0]}: Permission denied"
            else:
                output = fs[target]["content"]
                if target == "/opt/ctf/root_flag.txt":
                    solve()
                    output += "\n✓ 문제 해결!"
    elif cmd == "chmod":
        if len(args) != 2:
            output = "usage: chmod <mode> <file>"
        elif not re.fullmatch(r"[0-7]{3,4}", args[0]):
            output = "chmod: invalid mode"
        else:
            target = norm(args[1], cwd)
            if target not in fs:
                output = f"chmod: cannot access '{args[1]}': No such file or directory"
            else:
                fs[target]["mode"] = int(args[0][-3:], 8)
    elif cmd == "find":
        if len(args) >= 3 and args[0] == "/" and args[1] == "-name":
            output = "\n".join(
                path for path in fs if path.rsplit("/", 1)[-1] == args[2]
            )
        else:
            output = "find: unsupported expression"
    else:
        output = f"{cmd}: command not found"

    return jsonify(output=output, cwd=cwd)


@app.route("/cookie-challenge")
def cookie_challenge():
    user = current_user()
    if not user or user["is_admin"]:
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
    if not user or user["is_admin"]:
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


@app.route("/admin/status")
def admin_status():
    user = current_user()
    if not user:
        return {"error": "login required"}, 401
    if not user["is_admin"]:
        return {"error": "admin only"}, 403

    conn = get_db()
    rows = conn.execute("""
        SELECT u.username, u.ip_address, s.problem_id, s.solved_at
        FROM solves s
        JOIN users u ON u.id = s.user_id
        ORDER BY s.solved_at DESC
    """).fetchall()
    conn.close()

    return {
        "solves": [
            {
                "username": r["username"],
                "ip_address": r["ip_address"],
                "problem_id": r["problem_id"],
                "solved_at": r["solved_at"]
            }
            for r in rows
        ]
    }


@app.route("/admin")
def admin():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not user["is_admin"]:
        return "관리자만 접근할 수 있습니다.", 403

    conn = get_db()
    users = conn.execute(
        "SELECT id, username, created_at, ip_address FROM users WHERE is_admin = 0 ORDER BY id ASC"
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


@app.route("/admin/user/<int:user_id>/reset-password", methods=["POST"])
def admin_reset_password(user_id):
    user = current_user()
    if not user or not user["is_admin"]:
        return "관리자만 접근할 수 있습니다.", 403

    new_password = request.form.get("new_password", "")
    if len(new_password) < 6:
        flash("새 비밀번호는 6자 이상이어야 합니다.", "error")
        return redirect(url_for("admin"))

    conn = get_db()
    target = conn.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target or target["is_admin"]:
        conn.close()
        flash("변경할 수 없는 사용자입니다.", "error")
        return redirect(url_for("admin"))

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()
    flash(f"{target['username']} 사용자의 비밀번호를 변경했습니다.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/kick", methods=["POST"])
def admin_kick_user(user_id):
    user = current_user()
    if not user or not user["is_admin"]:
        return "관리자만 접근할 수 있습니다.", 403

    conn = get_db()
    target = conn.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target or target["is_admin"]:
        conn.close()
        flash("추방할 수 없는 사용자입니다.", "error")
        return redirect(url_for("admin"))

    conn.execute("DELETE FROM solves WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash(f"{target['username']} 사용자를 추방했습니다.", "success")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    init_main_db()
    init_sqli_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
