"""
Client Screen Guard — Mərkəzi Auth Server (vahid bazalı login).

Bu server BÜTÜN müştəri quraşdırmaları üçün tək (vahid) istifadəçi bazasını
saxlayır. Proqram (EXE) login/parolu bura göndərir, server yoxlayır.

Xüsusiyyətlər
─────────────
- SQLite baza (server_users.db) — bir mərkəzdə bütün istifadəçilər.
- Token əsaslı sessiya (login -> token -> admin əməliyyatları token ilə).
- Server tərəfində lockout (brute-force qoruması) və parol siyasəti.
- PBKDF2-HMAC-SHA256 parol hash-ı (200k iterasiya).
- Əlavə asılılıq YOXDUR (yalnız Python standart kitabxanası).

TLS / HTTPS
───────────
Bu server HTTP verir. İnternetdə istifadə üçün onu nginx / Caddy kimi reverse
proxy arxasına qoy və TLS-i orada bitir (məs. https://auth.senin-domenin.az ->
127.0.0.1:8777). Beləliklə client HTTPS ilə danışır.

İşə salmaq
──────────
    python auth_server.py
    # və ya konfiqurasiya ilə:
    set CSG_HOST=0.0.0.0 & set CSG_PORT=8777 & python auth_server.py

Bootstrap admin: ilk işə salındıqda yaradılır -> admin / ChangeMe123!
(ilk girişdə dəyişdirilməlidir).
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import relay
import ws_lite

# Çıxış (stdout/stderr) həmişə UTF-8 olsun — server.log-a yönləndiriləndə
# Azərbaycan hərfləri (ş, ə) UnicodeEncodeError verib serveri çökdürməsin.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# Konfiqurasiya (mühit dəyişənləri ilə override oluna bilər)
# --------------------------------------------------------------------------- #
HOST = os.getenv("CSG_HOST", "127.0.0.1")
PORT = int(os.getenv("CSG_PORT", "8777"))
DB_FILE = os.getenv(
    "CSG_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_users.db"),
)
TOKEN_TTL_SECONDS = int(os.getenv("CSG_TOKEN_TTL", str(12 * 3600)))  # 12 saat

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
MIN_PASSWORD_LEN = 8
MIN_USERNAME_LEN = 3

_DB_LOCK = threading.Lock()


def db_one(sql: str, params: tuple = ()):
    """Kilidlənmiş TƏK-sətir oxuma. `CONN` `ThreadingHTTPServer`-in bütün
    request-thread-ləri arasında BİR sqlite3 connection-dur — sqlite3
    `check_same_thread=False` yalnız eyni-thread yoxlamasını söndürür,
    connection-a HƏQİQİ paralel girişi TƏHLÜKƏSİZ etmir. Əvvəllər YAZMALAR
    `_DB_LOCK` ilə qorunurdu, amma OXUMALAR qorunmurdu — real çoxlu-müştəri
    yükü altında bu, `sqlite3.InterfaceError: bad parameter or other API
    misuse` xətalarına səbəb olurdu (təsdiqlənib)."""
    with _DB_LOCK:
        return CONN.execute(sql, params).fetchone()


def db_all(sql: str, params: tuple = ()):
    """Kilidlənmiş ÇOX-sətir oxuma — bax `db_one` qeydi."""
    with _DB_LOCK:
        return CONN.execute(sql, params).fetchall()

# --------------------------------------------------------------------------- #
# Telegram (DƏSTƏK chat) — token YALNIZ serverdə saxlanılır, EXE-yə getmir.
# Prioritet: CSG_TELEGRAM_TOKEN env → server/telegram_token.txt faylı.
# --------------------------------------------------------------------------- #

def _load_tg_token() -> str:
    tok = os.getenv("CSG_TELEGRAM_TOKEN", "").strip()
    if tok:
        return tok
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "telegram_token.txt")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        return line
        except Exception:
            pass
    return ""

TG_TOKEN = _load_tg_token()
TG_API = f"https://api.telegram.org/bot{TG_TOKEN}"


# --------------------------------------------------------------------------- #
# API açarı — kənar (icazəsiz) sorğuları bloklamaq üçün.
# Prioritet: CSG_API_KEY env → server/api_key.txt. Boşdursa yoxlama YOXDUR.
# --------------------------------------------------------------------------- #

def _load_api_key() -> str:
    key = os.getenv("CSG_API_KEY", "").strip()
    if key:
        return key
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_key.txt")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        return line
        except Exception:
            pass
    return ""

API_KEY = _load_api_key()
SERVER_START_TS = time.time()


# --------------------------------------------------------------------------- #
# Ən son client versiyası (#5 — MƏCBURİ auto-update).
# Prioritet: CSG_LATEST_VERSION env → server/latest_version.txt faylı → default.
# İlk sətir = versiya (məs. "1.0.0"), ikinci sətir (istəyə bağlı) = qeyd mətni,
# üçüncü sətir (istəyə bağlı) = GitHub Releases birbaşa endirmə linki.
# Fayl HƏR SORĞUDA təzədən oxunur (server yenidən başladılmadan dərhal təsir
# edir) — məcburi yeniləmə/kill-switch kimi işlədilə bilməsi üçün vacibdir.
# --------------------------------------------------------------------------- #

def _load_latest_version() -> tuple[str, str, str]:
    env_v = os.getenv("CSG_LATEST_VERSION", "").strip()
    if env_v:
        return (env_v, os.getenv("CSG_UPDATE_NOTES", "").strip(),
                os.getenv("CSG_UPDATE_URL", "").strip())
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latest_version.txt")
    if os.path.isfile(path):
        try:
            # "#" YALNIZ faylın BAŞINDAKI başlıq blokunda şərh sayılır. İlk
            # həqiqi (versiya) sətrindən sonra gələn sətirlər (qeyd/link)
            # "#" ilə başlasa belə MƏLUMAT kimi oxunur — əks halda operator
            # qeydində "#452 xətası düzəldildi" kimi bir şey yazsa, o sətir
            # səhvən şərh sayılıb atılır və növbəti sətir (link) onun yerinə
            # sürüşür, endirmə linki tamamilə itir (təsdiqlənmiş bug).
            lines = []
            past_header = False
            for raw in open(path, "r", encoding="utf-8"):
                ln = raw.strip()
                if not past_header:
                    if not ln or ln.startswith("#"):
                        continue
                    past_header = True
                lines.append(ln)
            while lines and not lines[-1]:
                lines.pop()
            if lines:
                return (lines[0],
                        lines[1] if len(lines) > 1 else "",
                        lines[2] if len(lines) > 2 else "")
        except Exception:
            pass
    return "1.0.0", "", ""


# --------------------------------------------------------------------------- #
# Parol hash / siyasət
# --------------------------------------------------------------------------- #

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


# Mövcud olmayan istifadəçi adı üçün istifadə olunan "boş" hash — vaxt
# sızması (timing side-channel) qarşısını almaq üçün: PBKDF2 200k iterasiya
# ~100-200ms çəkir; bunu YALNIZ mövcud hesablar üçün çağırsaq, mövcud
# olmayan username-lər demək olar ki, ANİ cavab alır — bu fərq username
# siyahıya alma (enumeration) üçün ölçülə bilən siqnaldır.
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(16))


def validate_password_strength(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LEN:
        return f"Parol ən azı {MIN_PASSWORD_LEN} simvol olmalıdır."
    if not re.search(r"[A-Za-z]", password):
        return "Parolda ən azı bir hərf olmalıdır."
    if not re.search(r"\d", password):
        return "Parolda ən azı bir rəqəm olmalıdır."
    return None


# --------------------------------------------------------------------------- #
# Baza
# --------------------------------------------------------------------------- #

def _connect() -> sqlite3.connect:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


CONN = _connect()


def init_db() -> None:
    with _DB_LOCK:
        cur = CONN.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0,
                license_active INTEGER NOT NULL DEFAULT 0,
                license_expires TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at REAL NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                direction TEXT NOT NULL,   -- 'in' (müştəri→operator) | 'out' (operator→müştəri)
                text TEXT NOT NULL,
                ts TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS server_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                cmd TEXT NOT NULL,       -- lock | unlock | say
                arg TEXT,
                ts TEXT NOT NULL
            )
            """
        )
        # QEYD: username sütunu COLLATE NOCASE — get_user()-in "R"=="r" davranışı
        # ilə UZLAŞMASI VACİBDİR, əks halda ID+Kod axını böyük/kiçik hərf
        # uyğunsuzluğu üzündən "Kod yanlışdır" ilə uğursuz olur (real tapılmış
        # bug). Köhnə (NOCASE-siz) versiyalarını miqrasiya et — bu cədvəllər
        # tamamilə EFEMER-dir (hər login-də yenidən yaranır), data itkisi
        # ZƏRƏRSIZDIR.
        _table_defs = {
            "connect_codes": """
                CREATE TABLE IF NOT EXISTS connect_codes (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    code TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """,
            "screen_share_sessions": """
                CREATE TABLE IF NOT EXISTS screen_share_sessions (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    ip TEXT, port INTEGER, token TEXT,
                    created_at TEXT NOT NULL
                )
            """,
        }
        for _tbl, _create_sql in _table_defs.items():
            row = cur.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_tbl,)
            ).fetchone()
            if row and "COLLATE NOCASE" not in (row["sql"] or ""):
                cur.execute(f"DROP TABLE {_tbl}")
            cur.execute(_create_sql)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                admin TEXT NOT NULL,     -- əməliyyatı icra edən admin
                action TEXT NOT NULL,    -- add_user | delete_user | reset_password | ...
                target TEXT,             -- əməliyyata məruz qalan istifadəçi
                detail TEXT
            )
            """
        )
        # Köhnə bazalara lisenziya sütunlarını əlavə et (geriyə uyğunluq)
        existing = {r["name"] for r in cur.execute("PRAGMA table_info(users)")}
        if "license_active" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN license_active INTEGER NOT NULL DEFAULT 0")
        if "license_expires" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN license_expires TEXT")

        cur.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()["c"] == 0:
            cur.execute(
                "INSERT INTO users(username,password_hash,role,must_change_password,"
                "created_at) VALUES(?,?,?,1,?)",
                ("admin", hash_password("ChangeMe123!"), "admin",
                 datetime.now(timezone.utc).isoformat()),
            )
            print("Bootstrap admin yaradıldı: admin / ChangeMe123! "
                  "(ilk girişdə dəyişdirilməlidir)")
        CONN.commit()


# --------------------------------------------------------------------------- #
# İstifadəçi / sessiya əməliyyatları
# --------------------------------------------------------------------------- #

def norm_username(u: str) -> str:
    """Standart: istifadəçi adı — boşluqsuz və kiçik hərflə."""
    return (u or "").strip().lower()


def get_user(username: str):
    # Böyük/kiçik hərfə HƏSSAS DEYİL (NOCASE) — "Ali"=="ali"=="ALI"
    return db_one(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
        (norm_username(username),)
    )


def get_user_by_id(user_id: int):
    return db_one("SELECT * FROM users WHERE id=?", (user_id,))


def count_admins() -> int:
    return db_one(
        "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1"
    )["c"]


def issue_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + TOKEN_TTL_SECONDS
    with _DB_LOCK:
        CONN.execute(
            "INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)",
            (token, user_id, expires),
        )
        # köhnəlmiş sessiyaları təmizlə
        CONN.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        CONN.commit()
    return token


def user_for_token(token: str):
    if not token:
        return None
    row = db_one(
        "SELECT * FROM sessions WHERE token=?", (token,)
    )
    if not row or row["expires_at"] < time.time():
        return None
    return get_user_by_id(row["user_id"])


# --------------------------------------------------------------------------- #
# State + chat (DƏSTƏK) saxlama
# --------------------------------------------------------------------------- #

def state_get(key: str, default: str = "") -> str:
    row = db_one("SELECT value FROM server_state WHERE key=?", (key,))
    return row["value"] if row else default


def state_set(key: str, value: str) -> None:
    with _DB_LOCK:
        CONN.execute(
            "INSERT INTO server_state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        CONN.commit()


def chat_add(username: str, direction: str, text: str) -> int:
    with _DB_LOCK:
        cur = CONN.execute(
            "INSERT INTO chat_messages(username,direction,text,ts) VALUES(?,?,?,?)",
            (username, direction, text,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        CONN.commit()
        return cur.lastrowid


def chat_since(username: str, since_id: int):
    # COLLATE NOCASE: get_user()-lə eyni prinsip — "R"/"r" fərqli hesab
    # sayılmasın (operator Telegram-da başqa hərf registri yazsa belə).
    return db_all(
        "SELECT id,text,ts FROM chat_messages "
        "WHERE username=? COLLATE NOCASE AND direction='out' AND id>? ORDER BY id",
        (username, since_id),
    )


def cmd_add(username: str, cmd: str, arg: str = "") -> int:
    with _DB_LOCK:
        cur = CONN.execute(
            "INSERT INTO commands(username,cmd,arg,ts) VALUES(?,?,?,?)",
            (username, cmd, arg,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        CONN.commit()
        return cur.lastrowid


def cmd_since(username: str, since_id: int):
    # COLLATE NOCASE: get_user()-lə eyni prinsip — bax connect_code_verify-in
    # eyni problemi (böyük/kiçik hərf uyğunsuzluğu, "R" vs "r").
    return db_all(
        "SELECT id,cmd,arg FROM commands WHERE username=? COLLATE NOCASE AND id>? "
        "ORDER BY id",
        (username, since_id),
    )


# --------------------------------------------------------------------------- #
# TeamViewer-tərzi ID+Kod ilə qoşulma (ekran paylaşımı) — bax screen_share.py.
# Müştəri login edəndə kod (yenidən) yaradılır; operator ID(username)+kodu
# yazıb "Qoşul" edəndə server müştəriyə uzaqdan "start_screen_share" komandası
# göndərir (commands cədvəli ilə), müştərinin ekranı qaralır, ekran-paylaşımı
# başlayır və öz IP/token-ini bu cədvələ yazır ki, operator ala bilsin.
# --------------------------------------------------------------------------- #

CONNECT_CODE_TTL = 15 * 60      # kod bu qədər saniyə etibarlıdır
SCREEN_SHARE_SESSION_TTL = 60   # session_info bu qədər saniyədən köhnədirsə "yoxdur" sayılır


def connect_code_set(username: str, code: str) -> None:
    with _DB_LOCK:
        CONN.execute(
            "INSERT INTO connect_codes(username,code,created_at) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET code=excluded.code, "
            "created_at=excluded.created_at",
            (username, code, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        CONN.commit()


def connect_code_verify(username: str, code: str) -> bool:
    row = db_one(
        "SELECT code, created_at FROM connect_codes WHERE username=?", (username,)
    )
    if not row or not hmac.compare_digest(row["code"], code):
        return False
    try:
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - created).total_seconds()
    return age <= CONNECT_CODE_TTL


def screen_share_session_set(username: str, token: str) -> None:
    """QEYD: `ip`/`port` sütunları cədvəldə hələ FİZİKİ olaraq var (köhnə
    sxemdən qalıb, `CREATE TABLE IF NOT EXISTS` onları silmir), amma artıq
    YAZILMIR — relay modelində müştərinin IP-si lazım deyil, yalnız
    token (bax plan sənədi #4). NULL qalırlar, zərərsizdir."""
    with _DB_LOCK:
        CONN.execute(
            "INSERT INTO screen_share_sessions(username,token,created_at) "
            "VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET "
            "token=excluded.token, created_at=excluded.created_at",
            (username, token,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        CONN.commit()


def screen_share_session_clear(username: str) -> None:
    with _DB_LOCK:
        CONN.execute("DELETE FROM screen_share_sessions WHERE username=?", (username,))
        CONN.commit()


def screen_share_session_get(username: str):
    row = db_one(
        "SELECT token, created_at FROM screen_share_sessions WHERE username=?",
        (username,),
    )
    if not row:
        return None
    try:
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    age = (datetime.now(timezone.utc) - created).total_seconds()
    if age > SCREEN_SHARE_SESSION_TTL:
        return None
    return {"token": row["token"]}


def screen_share_token_is_valid(token: str) -> bool:
    """WS relay-ə qoşulmazdan ƏVVƏL çağırılır — token serverin ÖZÜ verdiyi
    (screen_share_sessions-də TƏZƏ qeyd olunmuş) bir sessiyaya aiddirmi?

    VACİB (bax plan sənədi #3): Radmin VPN silinəndə fiziki şəbəkə-üzvlüyü
    örtülü giriş qatı da yox olur — token artıq YEGANƏ sərhəd olur. Bu
    yoxlama olmasa, internetdəki istənilən kəs təsadüfi token yazıb
    `/relay`-ə qoşula, pulsuz thread yaradıb resurs tükəndirə bilər.
    """
    row = db_one(
        "SELECT created_at FROM screen_share_sessions WHERE token=?", (token,)
    )
    if not row:
        return False
    try:
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - created).total_seconds()
    return age <= SCREEN_SHARE_SESSION_TTL


_RELAY = relay.Relay()


# --------------------------------------------------------------------------- #
# Admin audit trail (#6) — hansı admin, nə vaxt, nə etdi.
# --------------------------------------------------------------------------- #

def audit(admin_username: str, action: str, target: str = "", detail: str = "") -> None:
    with _DB_LOCK:
        CONN.execute(
            "INSERT INTO audit_log(ts,admin,action,target,detail) VALUES(?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             admin_username, action, target, detail),
        )
        CONN.commit()
    print(f"[audit] {admin_username} -> {action} {target} {detail}".strip())


def audit_recent(limit: int = 200):
    return db_all(
        "SELECT ts, admin, action, target, detail FROM audit_log "
        "ORDER BY id DESC LIMIT ?", (limit,)
    )


# --------------------------------------------------------------------------- #
# Telegram körpüsü
# --------------------------------------------------------------------------- #

def tg_api(method: str, params: dict, timeout: int = 35):
    import urllib.parse
    import urllib.request
    url = f"{TG_API}/{method}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def tg_send(chat_id, text: str):
    try:
        tg_api("sendMessage", {"chat_id": chat_id, "text": text}, timeout=15)
    except Exception as e:
        print(f"[tg] sendMessage xəta: {e}")


_FWD_PREFIX = "💬 "   # forward mesajının başlanğıcı: "💬 <username>:"


def notify_operator(username: str, text: str):
    """Müştəri mesajını operatorun Telegram-ına ötürür (REPLY üçün hazır)."""
    op = state_get("tg_operator", "")
    if not op:
        return
    tg_send(op, f"{_FWD_PREFIX}{username}:\n{text}\n\n"
                f"↩️ Cavab: bu mesaja REPLY et (və ya: @{username} mesaj)")


def _target_from_reply(reply_text: str):
    """Forward mesajının mətnindən müştəri username-ini çıxarır."""
    if not reply_text:
        return None
    first = reply_text.split("\n", 1)[0].strip()
    if first.startswith(_FWD_PREFIX):
        name = first[len(_FWD_PREFIX):].strip()
        if name.endswith(":"):
            name = name[:-1]
        name = name.strip()
        return name.split()[0] if name else None
    return None


def recent_in_messages(limit: int = 20):
    """Ən son müştəri (in) mesajları — operator qeydə alınanda ötürmək üçün."""
    return db_all(
        "SELECT username, text FROM chat_messages WHERE direction='in' "
        "ORDER BY id DESC LIMIT ?", (limit,)
    )


def telegram_loop():
    """Operatorun cavablarını Telegram-dan alıb müştəri thread-inə yazır."""
    print("[tg] Telegram bridge aktiv (bot işləyir). Operator /start gözlənilir...")
    offset = int(state_get("tg_offset", "0") or "0")
    while True:
        try:
            data = tg_api("getUpdates", {"offset": offset, "timeout": 30})
        except Exception as e:
            print(f"[tg] getUpdates xəta: {e}")
            time.sleep(3)
            continue

        for u in data.get("result", []):
            offset = u["update_id"] + 1
            try:
                _handle_telegram_update(u)
            except Exception as e:
                # Bir update-in emalında gözlənilməyən xəta (məs. gözlənilməz
                # Telegram payload forması) bütün bu daemon thread-ini
                # ÖLDÜRMƏMƏLİDİR — əks halda DƏSTƏK Telegram körpüsü serverin
                # qalan ömrü boyu SƏSSİZCƏ sönür (əvvəllər bu blok yox idi).
                print(f"[tg] update emalı xətası (keçilir): {e}")

        state_set("tg_offset", str(offset))


def _handle_telegram_update(u: dict) -> None:
    msg = u.get("message") or u.get("edited_message") or {}
    chat = msg.get("chat", {})
    cid = chat.get("id")
    text = (msg.get("text") or "").strip()
    if cid is None:
        return

    op = state_get("tg_operator", "")
    if not op:                       # ilk yazan = operator (chat_id tut)
        state_set("tg_operator", str(cid))
        op = str(cid)
        tg_send(cid, "TexnikiEkran DƏSTƏK: operator qeydə alındı ✅\n"
                     "Müştəri mesajları buraya gələcək.\n"
                     "Cavab üçün mesaja REPLY et.")
        # Gözləyən müştəri mesajlarını ötür (yeniyə doğru)
        for row in reversed(recent_in_messages(20)):
            notify_operator(row["username"], row["text"])
        return
    if str(cid) != op:               # yalnız operatoru qəbul et
        return
    if not text or text.startswith("/start"):
        tg_send(cid, "Hazır.\n"
                     "• Cavab üçün müştəri mesajına REPLY et.\n"
                     "• Ekranı bağla:  /lock <istifadəçi>\n"
                     "• Ekranı aç:     /unlock <istifadəçi>\n"
                     "• Ekrana yazı:   /say <istifadəçi> <mətn>\n"
                     "(REPLY edərək yazsan, istifadəçi adı avtomatik seçilir)")
        return

    # Hədəf müştərini müəyyən et: REPLY → @username → sonuncu aktiv
    reply = msg.get("reply_to_message") or {}
    reply_target = _target_from_reply(reply.get("text", ""))

    # ── Uzaqdan komandalar (/lock /unlock /say) ──────────────────────────
    if text.startswith("/"):
        parts = text.split(None, 2)
        command = parts[0][1:].lower()
        target = reply_target
        arg = ""
        rest = parts[1:]
        if command in ("lock", "unlock", "say"):
            if not target and rest:
                target = rest[0]
                rest = rest[1:]
            if command == "say":
                arg = rest[0] if rest else ""
            if not target:
                tg_send(cid, "İstifadəçi göstərilməyib. Nümunə: /lock musteri")
                return
            cmd_add(target, command, arg)
            tg_send(cid, f"✓ '{command}' → {target} (icra gözlənilir)")
            return

    # ── Adi cavab (chat/təlimat) ───────────────────────────────────────────
    body = text
    target = reply_target
    if not target and text.startswith("@"):
        p = text[1:].split(None, 1)
        target = p[0]
        body = p[1] if len(p) > 1 else ""
    if not target:
        target = state_get("tg_last_user", "")
    if target and body:
        chat_add(target, "out", body)
        tg_send(cid, f"✓ {target}-ə göndərildi")


def start_telegram():
    if not TG_TOKEN:
        print("[tg] Telegram token yoxdur — DƏSTƏK chat deaktivdir.")
        return
    threading.Thread(target=telegram_loop, daemon=True).start()


# --------------------------------------------------------------------------- #
# Avtomatik baza ehtiyat nüsxəsi (backup)
# --------------------------------------------------------------------------- #

BACKUP_HOURS = int(os.getenv("CSG_BACKUP_HOURS", "6"))
BACKUP_KEEP = int(os.getenv("CSG_BACKUP_KEEP", "14"))
# QEYD: defolt olaraq DB_FILE-in ÖZ qovluğu (CSG_DB-yə görə) istifadə
# olunur — __file__-in qovluğu YOX. Render kimi platformalarda konteynerin
# öz fayl sistemi hər deploy-da sıfırlanır; CSG_DB adətən qoşulmuş
# Disk-ə göstərilir, backup-lar da EYNİ diskə düşməlidir, əks halda
# səssizcə itər (əvvəllər tapılmış bug — bax plan sənədi).
BACKUP_DIR = os.getenv(
    "CSG_BACKUP_DIR",
    os.path.join(os.path.dirname(os.path.abspath(DB_FILE)), "backups"),
)


def backup_loop():
    import glob
    bdir = BACKUP_DIR
    os.makedirs(bdir, exist_ok=True)
    while True:
        try:
            if os.path.isfile(DB_FILE):
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                dst = os.path.join(bdir, f"users_{ts}.db")
                # SQLite backup API — açıq baza ilə də təhlükəsiz kopya
                src = sqlite3.connect(DB_FILE)
                dstc = sqlite3.connect(dst)
                with dstc:
                    src.backup(dstc)
                src.close()
                dstc.close()
                files = sorted(glob.glob(os.path.join(bdir, "users_*.db")))
                for f in files[:-BACKUP_KEEP]:
                    try:
                        os.remove(f)
                    except Exception:
                        pass
                print(f"[backup] {dst}")
        except Exception as e:
            print(f"[backup] xəta: {e}")
        time.sleep(max(1, BACKUP_HOURS) * 3600)


def start_backup():
    threading.Thread(target=backup_loop, daemon=True).start()


# --------------------------------------------------------------------------- #
# Proaktiv lisenziya bitmə xəbərdarlığı (#3) — operatora gündə bir dəfə Telegram
# hesabatı: tezliklə bitən / artıq bitmiş lisenziyalar.
# --------------------------------------------------------------------------- #

LICENSE_WARN_DAYS = int(os.getenv("CSG_LICENSE_WARN_DAYS", "3"))


def _send_license_digest_if_due() -> None:
    op = state_get("tg_operator", "")
    if not op:
        return
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if state_get("license_digest_date", "") == today:
        return
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=LICENSE_WARN_DAYS)
    rows = db_all(
        "SELECT username, license_expires FROM users "
        "WHERE license_active=1 AND license_expires IS NOT NULL"
    )
    expiring, expired = [], []
    for r in rows:
        try:
            exp_dt = datetime.fromisoformat(r["license_expires"])
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if exp_dt < now:
            expired.append(r["username"])
        elif exp_dt <= soon:
            expiring.append((r["username"], (exp_dt - now).days))
    state_set("license_digest_date", today)
    if not expiring and not expired:
        return
    lines = ["📋 Lisenziya hesabatı:"]
    for name, days in sorted(expiring, key=lambda x: x[1]):
        lines.append(f"⚠️ {name}: {days} gün qalıb")
    for name in expired:
        lines.append(f"🔴 {name}: müddəti bitib")
    tg_send(op, "\n".join(lines))


def license_digest_loop():
    while True:
        try:
            _send_license_digest_if_due()
        except Exception as e:
            print(f"[license] xəta: {e}")
        time.sleep(3600)  # hər saat yoxla, günə bir dəfə göndərir


def start_license_digest():
    threading.Thread(target=license_digest_loop, daemon=True).start()


# --------------------------------------------------------------------------- #
# server.log rotasiyası (#4) — run_server_headless.bat çıxışı server.log-a
# ">>" ilə əlavə edir, vaxt keçdikcə hədsiz böyüyə bilər. Fayl həddindən
# böyüyəndə köhnəsini server.log.1-ə köçürüb təzəsini açırıq (stdout/stderr
# fd-lərini yeni fayla yönləndirməklə — cmd-nin ">>" yönləndirməsi buna mane
# olmur, çünki fd səviyyəsində dəyişdiririk).
# --------------------------------------------------------------------------- #

LOG_FILE = os.getenv(
    "CSG_LOG_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log"),
)
LOG_MAX_BYTES = int(os.getenv("CSG_LOG_MAX_BYTES", str(5 * 1024 * 1024)))


def _rotate_log_if_needed() -> None:
    try:
        if not os.path.isfile(LOG_FILE):
            return  # interaktiv rejim (fayla yönləndirmə yoxdur) — heç nə etmə
        if os.path.getsize(LOG_FILE) < LOG_MAX_BYTES:
            return
        old = LOG_FILE + ".1"
        sys.stdout.flush()
        sys.stderr.flush()
        # Windows-da fayl açıq (fd 1/2 ona bağlı) ola-ola rename ALINMIR
        # (POSIX-dən fərqli olaraq) — "WinError 32: fayl başqa proses
        # tərəfindən istifadə olunur". Ona görə əvvəlcə fd 1/2-ni müvəqqəti
        # os.devnull-a yönləndirib köhnə handle-ı buraxırıq, SONRA rename
        # edirik, SONRA yeni fayla geri qoşuluruq (finally ilə — rename
        # uğursuz olsa belə fd 1/2 həmişə bir fayla bağlı qalsın).
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull_fd, sys.stdout.fileno())
        os.dup2(devnull_fd, sys.stderr.fileno())
        os.close(devnull_fd)
        try:
            if os.path.isfile(old):
                os.remove(old)
            os.rename(LOG_FILE, old)
        finally:
            new_fd = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            os.dup2(new_fd, sys.stdout.fileno())
            os.dup2(new_fd, sys.stderr.fileno())
            os.close(new_fd)
            for _stream in (sys.stdout, sys.stderr):
                try:
                    _stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass
        print(f"[log] rotasiya edildi (> {LOG_MAX_BYTES} bayt) -> {old}")
    except Exception as e:
        print(f"[log] rotasiya xətası: {e}")


def log_rotate_loop():
    while True:
        _rotate_log_if_needed()
        time.sleep(600)  # hər 10 dəqiqədə bir yoxla


def start_log_rotation():
    threading.Thread(target=log_rotate_loop, daemon=True).start()


# --------------------------------------------------------------------------- #
# İş məntiqi (handler-lər)
# --------------------------------------------------------------------------- #

class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def license_valid(row) -> bool:
    """Hesabın lisenziyası aktivdirmi və vaxtı bitməyibmi?"""
    if not row["license_active"]:
        return False
    exp = row["license_expires"]
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        if datetime.now(timezone.utc) > exp_dt:
            return False
    return True


def _public_user(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "must_change_password": bool(row["must_change_password"]),
        "active": bool(row["active"]),
        "license_active": bool(row["license_active"]),
        "license_expires": row["license_expires"],
        "license_valid": license_valid(row),
        "created_at": row["created_at"],
    }


def do_login(body: dict) -> dict:
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    row = get_user(username)

    # Vaxt sızmasını azaltmaq üçün istifadəçi olmasa da yoxlama davam edir
    if row and row["locked_until"] > time.time():
        remaining = int(row["locked_until"] - time.time())
        raise ApiError(423, f"Hesab kilidlidir. {remaining} saniyə sonra cəhd edin.")

    # verify_password HƏMİŞƏ çağırılır (mövcud olmayan hesab üçün belə, "boş"
    # hash-a qarşı) ki, cavab vaxtı username-in mövcud olub-olmamasını
    # sızdırmasın — `or` qısaqapanması bunu əvvəllər YOX edirdi (təsdiqlənmiş
    # vaxt-sızması: mövcud olmayan username demək olar ki, ani cavab alırdı).
    stored_hash = row["password_hash"] if row else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, stored_hash)

    if not row or not row["active"] or not password_ok:
        if row:
            _record_failed(row["id"])
        raise ApiError(401, "Username və ya password yanlışdır.")

    _reset_failed(row["id"])
    token = issue_token(row["id"])
    # QEYD: "istifadəçi onlayn oldu" bildirişi qəsdən YOXDUR — operatora
    # Telegram-da YALNIZ həqiqi mesajlar (chat_send → notify_operator)
    # gəlsin deyə, giriş zamanı ayrıca bildiriş göndərilmir.
    return {"token": token, "user": _public_user(row)}


def _record_failed(user_id: int) -> None:
    # Oxu + hesabla + yaz HAMISI eyni kilid altında olmalıdır — əks halda
    # paralel (eyni anda çoxlu) yanlış-parol cəhdləri eyni köhnə
    # failed_attempts dəyərini oxuyub üst-üstə yazır (son yazan udur) və
    # 5-cəhd kilidlənməsi TAM YAN keçilə bilir (təsdiqlənmiş TOCTOU race).
    with _DB_LOCK:
        cur = CONN.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not cur:
            return
        attempts = cur["failed_attempts"] + 1
        locked_until = cur["locked_until"]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = time.time() + LOCKOUT_SECONDS
            attempts = 0
        CONN.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (attempts, locked_until, user_id),
        )
        CONN.commit()


def _reset_failed(user_id: int) -> None:
    with _DB_LOCK:
        CONN.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?",
            (user_id,),
        )
        CONN.commit()


def do_change_password(body: dict) -> dict:
    # QEYD: əvvəllər bu endpoint-də login-dəki 5-cəhd kilidlənməsi/uğursuz
    # cəhd izlənməsi YOX idi — bu, /api/login-də kilidlənmiş hesab olsa
    # belə, /api/change-password vasitəsilə limitsiz parol təxmin etmə
    # (sonda uğurlu təxmin hesabı ələ keçirir) oracle-ı yaradırdı
    # (təsdiqlənmiş boşluq). İndi do_login ilə EYNİ qorunma tətbiq olunur.
    username = (body.get("username") or "").strip()
    old = body.get("old_password") or ""
    new = body.get("new_password") or ""
    row = get_user(username)

    if row and row["locked_until"] > time.time():
        remaining = int(row["locked_until"] - time.time())
        raise ApiError(423, f"Hesab kilidlidir. {remaining} saniyə sonra cəhd edin.")

    if not row or not row["active"] or not verify_password(old, row["password_hash"]):
        if row:
            _record_failed(row["id"])
        raise ApiError(401, "Cari parol yanlışdır.")

    problem = validate_password_strength(new)
    if problem:
        raise ApiError(400, problem)
    with _DB_LOCK:
        CONN.execute(
            "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
            (hash_password(new), row["id"]),
        )
        CONN.commit()
    _reset_failed(row["id"])
    return {"ok": True}


def _require_admin(token: str):
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    if user["role"] != "admin":
        raise ApiError(403, "Bu əməliyyat yalnız admin üçündür.")
    return user


def do_list_users(token: str) -> dict:
    _require_admin(token)
    rows = db_all("SELECT * FROM users ORDER BY id")
    return {"users": [_public_user(r) for r in rows]}


def _expiry_from_days(days) -> str | None:
    """days>0 -> ISO bitmə tarixi, əks halda None (müddətsiz)."""
    try:
        days = int(days)
    except (TypeError, ValueError):
        return None
    if days > 0:
        return (datetime.now(timezone.utc).replace(microsecond=0)
                + timedelta(days=days)).isoformat()
    return None


def do_add_user(token: str, body: dict) -> dict:
    admin = _require_admin(token)
    username = norm_username(body.get("username"))   # standart: kiçik hərf
    password = body.get("password") or ""
    role = (body.get("role") or "user").lower()
    must_change = 1 if body.get("must_change", False) else 0
    if len(username) < MIN_USERNAME_LEN:
        raise ApiError(400, f"Username ən azı {MIN_USERNAME_LEN} simvol olmalıdır.")
    if role not in ("admin", "user"):
        raise ApiError(400, "Role admin və ya user olmalıdır.")
    problem = validate_password_strength(password)
    if problem:
        raise ApiError(400, problem)
    # Hərf-variant dublikatları da bloklа ("Ali" varsa "ali" yaradıla bilməz)
    if get_user(username):
        raise ApiError(409, "Bu username artıq mövcuddur.")

    # Lisenziya hesabla yaradılma anında təyin oluna bilər
    license_active = 1 if body.get("license_active", False) else 0
    license_expires = _expiry_from_days(body.get("license_days")) if license_active else None

    try:
        with _DB_LOCK:
            CONN.execute(
                "INSERT INTO users(username,password_hash,role,must_change_password,"
                "license_active,license_expires,created_at) VALUES(?,?,?,?,?,?,?)",
                (username, hash_password(password), role, must_change,
                 license_active, license_expires,
                 datetime.now(timezone.utc).isoformat()),
            )
            CONN.commit()
    except sqlite3.IntegrityError:
        raise ApiError(409, "Bu username artıq mövcuddur.")
    audit(admin["username"], "add_user", username, f"role={role}")
    return {"ok": True}


def do_set_license(token: str, body: dict) -> dict:
    admin = _require_admin(token)
    user_id = body.get("id")
    active = 1 if body.get("active", False) else 0
    row = get_user_by_id(user_id) if user_id is not None else None
    if not row:
        raise ApiError(404, "İstifadəçi tapılmadı.")
    expires = _expiry_from_days(body.get("days")) if active else None
    with _DB_LOCK:
        CONN.execute(
            "UPDATE users SET license_active=?, license_expires=? WHERE id=?",
            (active, expires, user_id),
        )
        CONN.commit()
    audit(admin["username"], "set_license", row["username"],
          f"active={bool(active)} expires={expires}")
    return {"ok": True, "license_active": bool(active), "license_expires": expires}


def do_delete_user(token: str, body: dict) -> dict:
    admin = _require_admin(token)
    user_id = body.get("id")
    row = get_user_by_id(user_id) if user_id is not None else None
    if not row:
        raise ApiError(404, "İstifadəçi tapılmadı.")
    if row["username"] == admin["username"]:
        raise ApiError(400, "Öz hesabınızı silə bilməzsiniz.")
    if row["role"] == "admin" and count_admins() <= 1:
        raise ApiError(400, "Bu, yeganə admin hesabıdır. Silmək olmaz.")
    with _DB_LOCK:
        CONN.execute("DELETE FROM users WHERE id=?", (user_id,))
        CONN.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        CONN.commit()
    audit(admin["username"], "delete_user", row["username"])
    return {"ok": True}


def do_reset_password(token: str, body: dict) -> dict:
    admin = _require_admin(token)
    user_id = body.get("id")
    new = body.get("new_password") or ""
    row = get_user_by_id(user_id) if user_id is not None else None
    if not row:
        raise ApiError(404, "İstifadəçi tapılmadı.")
    problem = validate_password_strength(new)
    if problem:
        raise ApiError(400, problem)
    with _DB_LOCK:
        # admin sıfırlayanda istifadəçi növbəti girişdə dəyişməyə məcbur olsun
        CONN.execute(
            "UPDATE users SET password_hash=?, must_change_password=1, "
            "failed_attempts=0, locked_until=0 WHERE id=?",
            (hash_password(new), user_id),
        )
        CONN.commit()
    audit(admin["username"], "reset_password", row["username"])
    return {"ok": True}


def do_chat_send(token: str, body: dict) -> dict:
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    text = (body.get("message") or "").strip()
    if not text:
        raise ApiError(400, "Boş mesaj.")
    mid = chat_add(user["username"], "in", text)
    state_set("tg_last_user", user["username"])
    notify_operator(user["username"], text)
    return {"ok": True, "id": mid}


def do_admin_chat_list(token: str) -> dict:
    """(admin) DƏSTƏK yazmış bütün "user" hesablarının siyahısı — son mesaj +
    cavabsız olub-olmadığı (# admin in-app cavab yaza bilsin, Telegram-a
    baxmadan)."""
    _require_admin(token)
    rows = db_all(
        "SELECT username FROM users WHERE role='user' ORDER BY username COLLATE NOCASE"
    )
    out = []
    for r in rows:
        uname = r["username"]
        last = db_one(
            "SELECT id, text, ts, direction FROM chat_messages "
            "WHERE username=? COLLATE NOCASE ORDER BY id DESC LIMIT 1",
            (uname,),
        )
        if not last:
            continue   # heç yazışmayan hesabları göstərmə
        pending = db_one(
            "SELECT 1 FROM chat_messages WHERE username=? COLLATE NOCASE "
            "AND direction='in' AND id > COALESCE("
            "(SELECT MAX(id) FROM chat_messages WHERE username=? COLLATE NOCASE "
            "AND direction='out'), 0) LIMIT 1",
            (uname, uname),
        )
        out.append({
            "username": uname,
            "last_text": last["text"],
            "last_ts": last["ts"],
            "pending": bool(pending),
        })
    out.sort(key=lambda x: x["last_ts"], reverse=True)
    return {"chats": out}


def do_admin_chat_history(token: str, username: str) -> dict:
    """(admin) Konkret müştəri ilə TAM yazışma tarixçəsi (hər iki istiqamət)."""
    _require_admin(token)
    username = norm_username(username)
    if not get_user(username):
        raise ApiError(404, "İstifadəçi tapılmadı.")
    rows = db_all(
        "SELECT id, direction, text, ts FROM chat_messages "
        "WHERE username=? COLLATE NOCASE ORDER BY id",
        (username,),
    )
    return {"messages": [
        {"id": r["id"], "direction": r["direction"], "text": r["text"], "ts": r["ts"]}
        for r in rows
    ]}


def do_admin_chat_send(token: str, body: dict) -> dict:
    """(admin) Konkret müştəriyə birbaşa proqram-daxili cavab göndərir
    (Telegram-a ehtiyac olmadan — eyni chat_messages axınına yazır, müştərinin
    öz poll dövrü bunu adi DƏSTƏK cavabı kimi görür)."""
    _require_admin(token)
    username = norm_username(body.get("username"))
    text = (body.get("message") or "").strip()
    if not text:
        raise ApiError(400, "Boş mesaj.")
    if not get_user(username):
        raise ApiError(404, "İstifadəçi tapılmadı.")
    mid = chat_add(username, "out", text)
    return {"ok": True, "id": mid}


def do_remote_access_notify(token: str, body: dict) -> dict:
    """Müştərinin RDP uzaqdan-giriş vəziyyətini operatora Telegram ilə çatdırır.

    Server heç bir parolu/İP-ni SAXLAMIR — sadəcə ötürür (chat_send-dəki
    notify_operator ilə eyni prinsip).
    """
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    op = state_get("tg_operator", "")
    if not op:
        raise ApiError(409, "Operator hələ qeydə alınmayıb (Telegram botla /start yazılmayıb).")

    action = (body.get("action") or "").strip()
    ip = (body.get("ip") or "naməlum").strip()
    username = (body.get("username") or "").strip()

    if action == "grant":
        password = (body.get("password") or "").strip()
        port = int(body.get("port") or 3389)
        minutes = int(body.get("expires_minutes") or 0)
        lines = [
            "🖥 UZAQDAN GİRİŞ (RDP) AÇILDI",
            f"👤 Müştəri: {user['username']}",
            f"🌐 IP: {ip}:{port}",
            f"🔑 İstifadəçi: {username}",
            f"🔒 Müvəqqəti parol: {password}",
        ]
        if minutes > 0:
            lines.append(f"⏱ {minutes} dəqiqə sonra avtomatik bağlanacaq.")
        tg_send(op, "\n".join(lines))
    elif action == "revoke":
        tg_send(op, f"🔒 Uzaqdan giriş bağlandı — müştəri: {user['username']}")
    else:
        raise ApiError(400, "Naməlum action.")

    return {"ok": True}


def do_screen_share_notify(token: str, body: dict) -> dict:
    """Müştərinin ekran-paylaşımı token-ini qeydə alır (özünə-xidmət
    "Başlat" axını üçün — operator bunu `do_get_screen_share_session`
    vasitəsilə pollayır). Admin-başladan (ID+Kod) axında token artıq
    `do_connect_by_code`-da BİRBAŞA qeydə alınır, bu çağırış həmin halda
    təkrar/artıqdır amma zərərsizdir (eyni tokeni yenidən yazır).

    QEYD: "başladı"/"bitdi" Telegram bildirişi QƏSDƏN YOXDUR — yalnız
    gərəksiz "səs-küy" yaradırdı. VACİB: bu, həm də `screen_share_sessions`
    cədvəlini doldurur ki, `/relay` bu token-i "server-in özü verdiyi"
    kimi tanısın (bax `screen_share_token_is_valid`) — relay-ə qoşulmadan
    ƏVVƏL çağırılmalıdır.
    """
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")

    action = (body.get("action") or "").strip()
    if action == "start":
        share_token = (body.get("token") or "").strip()
        if not share_token:
            raise ApiError(400, "Token boşdur.")
        screen_share_session_set(norm_username(user["username"]), share_token)
    elif action == "stop":
        screen_share_session_clear(norm_username(user["username"]))
    else:
        raise ApiError(400, "Naməlum action.")

    return {"ok": True}


def do_set_connect_code(token: str, body: dict) -> dict:
    """Müştəri login edəndə öz ID+Kod-unu (TeamViewer-tərzi) qeydə alır."""
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    code = (body.get("code") or "").strip()
    if not code:
        raise ApiError(400, "Kod boşdur.")
    connect_code_set(norm_username(user["username"]), code)
    return {"ok": True}


def do_connect_by_code(token: str, body: dict) -> dict:
    """(admin) Operator ID(username)+Kodu yazıb 'Qoşul' edəndə: kodu
    doğrulayır, TOKEN-i BURADA (serverdə) yaradır, müştəriyə uzaqdan
    'start_screen_share' komandası ilə ötürür VƏ operatora cavabda
    dərhal qaytarır — operator artıq müştərinin "hazır" bildirməsini
    poll etməli deyil, birbaşa relay-ə qoşula bilər (relay-in özü 60
    saniyəyə qədər qarşı tərəfi gözləyir, bax server/relay.py).
    """
    _require_admin(token)
    username = norm_username(body.get("username"))
    code = (body.get("code") or "").strip()
    if not username or not code:
        raise ApiError(400, "ID və kod tələb olunur.")
    if not get_user(username):
        raise ApiError(404, "Bu ID ilə istifadəçi tapılmadı.")
    if not connect_code_verify(username, code):
        raise ApiError(401, "Kod yanlışdır və ya vaxtı bitib.")
    share_token = secrets.token_urlsafe(16)
    screen_share_session_set(username, share_token)
    cmd_add(username, "start_screen_share", share_token)
    return {"ok": True, "token": share_token}


def do_stop_screen_share_remote(token: str, body: dict) -> dict:
    """(admin) Operator izləyici pəncərəni bağlayanda: müştəriyə uzaqdan
    'stop_screen_share' komandası göndərir ki, host boş yerə işləməsin."""
    _require_admin(token)
    username = norm_username(body.get("username"))
    if not username:
        raise ApiError(400, "ID tələb olunur.")
    cmd_add(username, "stop_screen_share", "")
    return {"ok": True}


def do_get_screen_share_session(token: str, username: str) -> dict:
    """(admin) Özünə-xidmət ("Başlat") axını üçün: operator bu endpoint-i
    pollayaraq müştərinin özü yaratdığı token-i alır (admin-başladan
    ID+Kod axınında bu lazım deyil — token artıq `do_connect_by_code`-un
    cavabında dərhal gəlir)."""
    _require_admin(token)
    info = screen_share_session_get(norm_username(username))
    if not info:
        return {"ready": False}
    return {"ready": True, **info}


def do_chat_poll(token: str, since: int) -> dict:
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    rows = chat_since(user["username"], since)
    return {"messages": [{"id": r["id"], "text": r["text"], "ts": r["ts"]}
                         for r in rows]}


def do_commands_poll(token: str, since: int) -> dict:
    user = user_for_token(token)
    if not user:
        raise ApiError(401, "Sessiya bitib. Yenidən login edin.")
    rows = cmd_since(user["username"], since)
    return {"commands": [{"id": r["id"], "cmd": r["cmd"], "arg": r["arg"] or ""}
                         for r in rows]}


def do_set_active(token: str, body: dict) -> dict:
    admin = _require_admin(token)
    user_id = body.get("id")
    active = 1 if body.get("active", True) else 0
    row = get_user_by_id(user_id) if user_id is not None else None
    if not row:
        raise ApiError(404, "İstifadəçi tapılmadı.")
    if not active and row["role"] == "admin" and count_admins() <= 1:
        raise ApiError(400, "Yeganə admini deaktiv etmək olmaz.")
    if not active and row["username"] == admin["username"]:
        raise ApiError(400, "Öz hesabınızı deaktiv edə bilməzsiniz.")
    with _DB_LOCK:
        CONN.execute("UPDATE users SET active=? WHERE id=?", (active, user_id))
        if not active:
            CONN.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        CONN.commit()
    audit(admin["username"], "set_active", row["username"], f"active={bool(active)}")
    return {"ok": True}


def do_get_version() -> dict:
    version, notes, download_url = _load_latest_version()
    return {"version": version, "notes": notes, "download_url": download_url}


def do_list_audit(token: str, limit: int = 200) -> dict:
    _require_admin(token)
    rows = audit_recent(limit)
    return {"entries": [
        {"ts": r["ts"], "admin": r["admin"], "action": r["action"],
         "target": r["target"] or "", "detail": r["detail"] or ""}
        for r in rows
    ]}


def do_get_stats(token: str) -> dict:
    """Admin dashboard üçün ümumi mənzərə: müştəri sayı, lisenziya vəziyyəti,
    server uptime."""
    _require_admin(token)
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=LICENSE_WARN_DAYS)
    total_users = 0
    active_licenses = 0
    expiring_soon = 0
    expired = 0
    for r in db_all("SELECT license_active, license_expires FROM users"):
        total_users += 1
        if not r["license_active"]:
            continue
        exp = r["license_expires"]
        if not exp:
            active_licenses += 1
            continue
        try:
            exp_dt = datetime.fromisoformat(exp)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if exp_dt < now:
            expired += 1
        else:
            active_licenses += 1
            if exp_dt <= soon:
                expiring_soon += 1
    return {
        "total_users": total_users,
        "active_licenses": active_licenses,
        "expiring_soon": expiring_soon,
        "expired": expired,
        "warn_days": LICENSE_WARN_DAYS,
        "uptime_seconds": int(time.time() - SERVER_START_TS),
    }


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "CSGAuth/1.0"

    # Log-u sadələşdir
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def _send(self, status: int, payload: dict):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _check_api_key(self, path: str):
        """API açarı təyin olunubsa, hər sorğuda düzgün X-Api-Key tələb olunur."""
        if not API_KEY or path in ("/api/health", "/api/version"):
            return
        got = self.headers.get("X-Api-Key", "")
        if not hmac.compare_digest(got, API_KEY):
            raise ApiError(403, "İcazəsiz sorğu (API açarı yanlışdır).")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError(400, "JSON oxunmadı.")

    def _handle_relay(self, query: dict) -> None:
        """Ekran-paylaşımı WS relay: /relay?token=...&channel=FRAMES|INPUT|FILE

        QEYD: 101-ə keçdikdən sonra bu funksiya artıq `self._send(...)`
        işlətməMƏLİdir — connection artıq WS frame rejiminə keçib, adi HTTP
        cavabı yazmaq axını korlayar. `do_GET`-in xarici try/except-i
        yalnız BU FUNKSİYA ÇAĞIRILMAZDAN ƏVVƏLKİ (token yoxlaması kimi)
        xətalar üçün faydalıdır.
        """
        token = (query.get("token", [""])[0]) or ""
        channel = (query.get("channel", [""])[0]) or ""
        if channel not in ("FRAMES", "INPUT", "FILE"):
            self._send(400, {"error": "Yanlış kanal."})
            return
        if not token or not screen_share_token_is_valid(token):
            self._send(403, {"error": "Token etibarsızdır və ya vaxtı bitib."})
            return

        headers = {k.lower(): v for k, v in self.headers.items()}
        try:
            conn = ws_lite.server_handshake(headers, self.rfile.read, self.wfile.write)
        except ws_lite.WSError as e:
            self._send(400, {"error": f"WS handshake xətası: {e}"})
            return

        try:
            peer = _RELAY.rendezvous((token, channel), conn, timeout=relay.SLOT_TIMEOUT)
            if peer is None:
                conn.close()
                return
            relay.pump(conn, peer)
        except Exception as e:
            print(f"[relay] gözlənilməyən xəta: {e}")
            try:
                conn.close()
            except Exception:
                pass

    def do_GET(self):
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            self._check_api_key(path)
            if path == "/relay":
                self._handle_relay(query)
            elif path == "/api/health":
                self._send(200, {"ok": True, "service": "csg-auth"})
            elif path == "/api/version":
                self._send(200, do_get_version())
            elif path == "/api/users":
                self._send(200, do_list_users(self._bearer()))
            elif path == "/api/chat/poll":
                since = int((query.get("since", ["0"])[0]) or "0")
                self._send(200, do_chat_poll(self._bearer(), since))
            elif path == "/api/commands/poll":
                since = int((query.get("since", ["0"])[0]) or "0")
                self._send(200, do_commands_poll(self._bearer(), since))
            elif path == "/api/audit":
                limit = int((query.get("limit", ["200"])[0]) or "200")
                self._send(200, do_list_audit(self._bearer(), limit))
            elif path == "/api/stats":
                self._send(200, do_get_stats(self._bearer()))
            elif path == "/api/screen-share/session":
                username = (query.get("username", [""])[0]) or ""
                self._send(200, do_get_screen_share_session(self._bearer(), username))
            elif path == "/api/admin/chat/list":
                self._send(200, do_admin_chat_list(self._bearer()))
            elif path == "/api/admin/chat/history":
                username = (query.get("username", [""])[0]) or ""
                self._send(200, do_admin_chat_history(self._bearer(), username))
            else:
                self._send(404, {"error": "Tapılmadı."})
        except ApiError as e:
            self._send(e.status, {"error": e.message})
        except Exception as e:  # pragma: no cover
            self._send(500, {"error": f"Server xətası: {e}"})

    def do_POST(self):
        try:
            self._check_api_key(self.path)
            body = self._read_json()
            token = self._bearer()
            if self.path == "/api/login":
                self._send(200, do_login(body))
            elif self.path == "/api/change-password":
                self._send(200, do_change_password(body))
            elif self.path == "/api/users":
                self._send(200, do_add_user(token, body))
            elif self.path == "/api/users/delete":
                self._send(200, do_delete_user(token, body))
            elif self.path == "/api/users/reset-password":
                self._send(200, do_reset_password(token, body))
            elif self.path == "/api/users/set-active":
                self._send(200, do_set_active(token, body))
            elif self.path == "/api/users/set-license":
                self._send(200, do_set_license(token, body))
            elif self.path == "/api/chat/send":
                self._send(200, do_chat_send(token, body))
            elif self.path == "/api/admin/chat/send":
                self._send(200, do_admin_chat_send(token, body))
            elif self.path == "/api/remote-access/notify":
                self._send(200, do_remote_access_notify(token, body))
            elif self.path == "/api/screen-share/notify":
                self._send(200, do_screen_share_notify(token, body))
            elif self.path == "/api/connect-code/set":
                self._send(200, do_set_connect_code(token, body))
            elif self.path == "/api/screen-share/connect-by-code":
                self._send(200, do_connect_by_code(token, body))
            elif self.path == "/api/screen-share/stop-remote":
                self._send(200, do_stop_screen_share_remote(token, body))
            else:
                self._send(404, {"error": "Tapılmadı."})
        except ApiError as e:
            self._send(e.status, {"error": e.message})
        except Exception as e:  # pragma: no cover
            self._send(500, {"error": f"Server xətası: {e}"})


def _bind_server(host: str, port: int, attempts: int = 12, delay: float = 10.0):
    """HOST-a bağlanmağa cəhd edir (retry ilə).

    CSG_HOST konkret bir ünvana (məs. Radmin adapterinin IP-sinə) təyin
    olunubsa (#1 — kənar şəbəkələrdən təcridolunma üçün), Windows girişində
    avtostart zamanı Radmin adapteri hələ tam hazır olmaya bilər (boot zamanı
    yarış vəziyyəti). Bir dəfəlik uğursuzluqla serveri öldürmək əvəzinə, bir
    neçə dəfə bir az gözləyib yenidən cəhd edirik.
    """
    last_err = None
    for i in range(1, attempts + 1):
        try:
            return ThreadingHTTPServer((host, port), Handler)
        except OSError as e:
            last_err = e
            print(f"[bind] {host}:{port} ünvanına bağlanmaq alınmadı "
                  f"(cəhd {i}/{attempts}): {e}")
            if i < attempts:
                time.sleep(delay)
    raise last_err


def _maybe_start_loopback_mirror(host: str, port: int) -> None:
    """HOST konkret (məs. Radmin) ünvana bağlıdırsa (#1), əlavə olaraq
    127.0.0.1-də də dinləyən ikinci server başladır.

    Bu, server maşınının özündə lokal test/inzibati girişi rahat edir və
    client-in "bu kompüterdə (lokal)" aşkarlanmasını qoruyur (client
    127.0.0.1-ə TCP qoşularaq "server elə bu kompüterdədir" deyə bilir).
    Şəbəkə təhlükəsizliyinə TƏSİRİ YOXDUR: loopback həmişəki kimi yalnız bu
    kompüterin özündən əlçatandır, kənar şəbəkəyə açılmır.
    """
    if host in ("0.0.0.0", "127.0.0.1", "localhost", ""):
        return
    try:
        mirror = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"[bind] loopback güzgü (127.0.0.1:{port}) açılmadı: {e}")
        return
    threading.Thread(target=mirror.serve_forever, daemon=True).start()
    print(f"Loopback güzgü aktiv: http://127.0.0.1:{port} (yalnız bu kompüterdən)")


def main():
    init_db()
    start_telegram()
    start_backup()
    start_license_digest()
    start_log_rotation()
    httpd = _bind_server(HOST, PORT)
    _maybe_start_loopback_mirror(HOST, PORT)
    print(f"Auth server işləyir: http://{HOST}:{PORT}")
    print(f"Baza: {DB_FILE}")
    print(f"DƏSTƏK chat (Telegram): {'aktiv' if TG_TOKEN else 'deaktiv'}")
    print(f"API açarı qoruması: {'aktiv' if API_KEY else 'DEAKTIV (hər kəs sorğu ata bilər)'}")
    print(f"Avtomatik backup: hər {BACKUP_HOURS} saatda (son {BACKUP_KEEP} nüsxə)")
    print(f"Lisenziya bitmə xəbərdarlığı: {LICENSE_WARN_DAYS} gün qala (operatora Telegram)")
    print(f"Son client versiyası: {_load_latest_version()[0]}")
    print("Dayandırmaq üçün Ctrl+C.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDayandırılır...")
        httpd.shutdown()


if __name__ == "__main__":
    main()
