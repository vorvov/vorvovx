import os
import sqlite3
import secrets
import string
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

DB_PATH  = os.environ.get("DB_PATH", os.path.join("/data", "vorvovx.db"))
JAR_PATH = os.environ.get("JAR_PATH", os.path.join("/data", "VorvovX-2.0.jar"))


# ─── DB ───────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            login        TEXT NOT NULL UNIQUE,
            password     TEXT NOT NULL,
            email        TEXT,
            role         TEXT DEFAULT 'User',
            subscription TEXT,
            hwid         TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS activation_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code   TEXT NOT NULL UNIQUE,
            days       INTEGER NOT NULL,
            used       INTEGER DEFAULT 0,
            used_by    INTEGER,
            used_at    TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS downloads (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip            TEXT,
            user_agent    TEXT,
            downloaded_at TEXT DEFAULT (datetime('now'))
        );
    """)
    # Тестовые данные при первом запуске
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        sub = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO users (login,password,email,role,subscription) VALUES (?,?,?,?,?)",
            ("admin", _hash_pw("admin123"), "admin@vorvovx.local", "Admin", sub)
        )
        conn.execute("INSERT INTO activation_keys (key_code,days) VALUES (?,?)", ("TEST-1234-5678-ABCD", 30))
        conn.execute("INSERT INTO activation_keys (key_code,days) VALUES (?,?)", ("PREM-XXXX-YYYY-ZZZZ", 90))
        conn.execute("INSERT INTO activation_keys (key_code,days) VALUES (?,?)", ("VIP0-0000-1111-2222", 365))
        conn.commit()
    conn.close()


def _hash_pw(plain: str) -> str:
    salt = secrets.token_hex(16)
    h = hmac.new(salt.encode(), plain.encode(), hashlib.sha256).hexdigest()
    return f"{salt}:{h}"


def _check_pw(plain: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        expected = hmac.new(salt.encode(), plain.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(h, expected)
    except Exception:
        return False


def ok(data=None, msg="OK"):
    r = {"success": True, "message": msg}
    if data:
        r.update(data)
    return jsonify(r), 200


def err(msg, code=400):
    return jsonify({"success": False, "message": msg}), code


# ─── INIT ─────────────────────────────────────
init_db()


# ─── ROUTES ───────────────────────────────────
@app.route("/")
def index():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return jsonify({"status": "VorvovX API", "version": "2.0", "users": total}), 200


# ── Логин ─────────────────────────────────────
@app.route("/loader.php", methods=["POST", "GET"])
@app.route("/loader",     methods=["POST", "GET"])
def loader():
    d     = request.get_json(silent=True) or request.form
    login = (d.get("login") or "").strip()
    pw    = d.get("pass") or ""
    if not login or not pw:
        return err("Введите логин и пароль")

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE login=? LIMIT 1", (login,)).fetchone()
    conn.close()

    if not row:
        return err("Пользователь не найден")
    if not _check_pw(pw, row["password"]):
        return err("Неверный пароль")

    sub = row["subscription"]
    if not sub or datetime.strptime(sub, "%Y-%m-%d %H:%M:%S") < datetime.utcnow():
        return err("Подписка истекла")

    return ok({"user": {
        "id":           row["id"],
        "login":        row["login"],
        "role":         row["role"],
        "subscription": row["subscription"],
        "hwid":         row["hwid"],
    }})


# ── Регистрация ───────────────────────────────
@app.route("/register.php", methods=["POST"])
@app.route("/register",     methods=["POST"])
def register():
    d     = request.get_json(silent=True) or request.form
    login = (d.get("login") or "").strip()
    pw    = d.get("password") or ""
    email = (d.get("email") or "").strip()
    key   = (d.get("key") or "").strip().upper()

    if not all([login, pw, email, key]):
        return err("Заполните все поля")
    if len(login) < 3 or len(login) > 20:
        return err("Логин должен быть 3–20 символов")
    if len(pw) < 6:
        return err("Пароль минимум 6 символов")

    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone():
        conn.close(); return err("Логин уже занят")
    if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        conn.close(); return err("Email уже зарегистрирован")

    key_row = conn.execute(
        "SELECT * FROM activation_keys WHERE key_code=? AND used=0 LIMIT 1", (key,)
    ).fetchone()
    if not key_row:
        conn.close(); return err("Неверный или использованный ключ активации")

    days    = key_row["days"]
    sub_end = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        "INSERT INTO users (login,password,email,role,subscription) VALUES (?,?,?,'User',?)",
        (login, _hash_pw(pw), email, sub_end)
    )
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "UPDATE activation_keys SET used=1,used_by=?,used_at=datetime('now') WHERE id=?",
        (uid, key_row["id"])
    )
    conn.commit()
    conn.close()
    return ok(msg="Регистрация успешна", data={"user_id": uid, "days": days})


# ── HWID ──────────────────────────────────────
@app.route("/bind_hwid.php", methods=["POST"])
@app.route("/bind_hwid",     methods=["POST"])
def bind_hwid():
    d       = request.get_json(silent=True) or request.form
    user_id = d.get("user_id")
    hwid    = (d.get("hwid") or "").strip()
    if not user_id or not hwid:
        return err("Не указан user_id или hwid")

    conn = get_db()
    row  = conn.execute("SELECT hwid FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        conn.close(); return err("Пользователь не найден")

    existing = row["hwid"] or ""
    if existing and existing != hwid:
        conn.close(); return err("HWID не совпадает")
    if not existing:
        conn.execute("UPDATE users SET hwid=? WHERE id=?", (hwid, user_id))
        conn.commit()
    conn.close()
    return ok(msg="HWID привязан")


# ── Скачать JAR ───────────────────────────────
@app.route("/download.php", methods=["GET"])
@app.route("/download",     methods=["GET"])
def download():
    if not os.path.isfile(JAR_PATH):
        return err("Файл клиента не найден на сервере", 404)
    conn = get_db()
    conn.execute(
        "INSERT INTO downloads (ip,user_agent) VALUES (?,?)",
        (request.remote_addr, request.headers.get("User-Agent","")[:255])
    )
    conn.commit()
    conn.close()
    return send_file(JAR_PATH, as_attachment=True,
                     download_name="VorvovX-2.0.jar",
                     mimetype="application/java-archive")


# ── Добавить юзера напрямую (admin) ──────────
@app.route("/add_user", methods=["POST"])
def add_user():
    d    = request.get_json(silent=True) or request.form
    tok  = d.get("token") or ""
    if tok != os.environ.get("ADMIN_TOKEN", "vorvovx2026"):
        return err("Нет доступа", 403)

    login = (d.get("login") or "").strip()
    pw    = d.get("password") or ""
    role  = d.get("role") or "User"
    days  = int(d.get("days") or 30)
    email = (d.get("email") or f"{login}@vorvovx.local").strip()

    if not login or not pw:
        return err("Укажите login и password")

    sub_end = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (login,password,email,role,subscription) VALUES (?,?,?,?,?)",
            (login, _hash_pw(pw), email, role, sub_end)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return err("Логин уже существует")
    conn.close()
    return ok(msg=f"Пользователь {login} создан", data={"days": days, "role": role})


# ── Добавить ключ (admin) ─────────────────────
@app.route("/add_key", methods=["POST"])
def add_key():
    d    = request.get_json(silent=True) or request.form
    tok  = d.get("token") or ""
    key  = (d.get("key") or "").strip().upper()
    days = int(d.get("days") or 30)

    if tok != os.environ.get("ADMIN_TOKEN", "vorvovx2026"):
        return err("Нет доступа", 403)

    if not key:
        alpha = string.ascii_uppercase + string.digits
        key   = "-".join("".join(secrets.choice(alpha) for _ in range(4)) for _ in range(4))

    conn = get_db()
    try:
        conn.execute("INSERT INTO activation_keys (key_code,days) VALUES (?,?)", (key, days))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return err("Ключ уже существует")
    conn.close()
    return ok(msg="Ключ создан", data={"key": key, "days": days})


# ── Статистика ────────────────────────────────
@app.route("/stats", methods=["GET"])
def stats():
    conn   = get_db()
    total  = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active = conn.execute(
        "SELECT COUNT(*) FROM users WHERE subscription > datetime('now')"
    ).fetchone()[0]
    dl     = conn.execute("SELECT COUNT(*) FROM downloads").fetchone()[0]
    keys   = conn.execute("SELECT COUNT(*) FROM activation_keys WHERE used=0").fetchone()[0]
    conn.close()
    return ok(data={"total_users": total, "active_users": active,
                    "total_downloads": dl, "available_keys": keys})
