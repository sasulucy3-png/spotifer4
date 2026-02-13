# bot_mail_codes.py
import os, re, time, json, imaplib, email, traceback, unicodedata, requests
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from email.utils import parseaddr

# ========= Config global =========
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
CHAT_ID   = os.getenv("CHAT_ID", "").strip()

MAX_ACCOUNTS = int(os.getenv("MAX_ACCOUNTS", "10"))

LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))
POLL_EVERY       = int(os.getenv("POLL_EVERY", "20"))

TG_MIN_INTERVAL_SEC = int(os.getenv("TG_MIN_INTERVAL_SEC", "2"))
CODE_COOLDOWN_MIN   = int(os.getenv("CODE_COOLDOWN_MIN", "5"))

ENABLE_COMMANDS = os.getenv("ENABLE_COMMANDS", "1") == "1"

# Filtros (ajusta a tu gusto)
ALLOWED_SENDERS = os.getenv("ALLOWED_SENDERS", "no-reply@alerts.spotify.com, alerts.spotify.com, spotify.com")
REQUIRED_SUBJECT_PATTERNS = os.getenv(
    "REQUIRED_SUBJECT_PATTERNS",
    r"(?=.*spotify)(?=.*(c[oó]digo|code|codice|accesso|inicio|login))"
)
DENY_CODE_VALUES = os.getenv("DENY_CODE_VALUES", "000000,555555")
ALLOW_BODY_FALLBACK = os.getenv("ALLOW_BODY_FALLBACK", "1")

# Diagnóstico:
DEBUG_LIST_ALL = os.getenv("DEBUG_LIST_ALL", "0") == "1"
SEARCH_ALL     = os.getenv("SEARCH_ALL", "0") == "1"

# 6 dígitos ASCII exactos + fallback Unicode
ASCII_CODE_RE = re.compile(r"([0-9]{6})")
UNICODE_CODE_RE = re.compile(r"(\d{6})", re.UNICODE)

# Persistencia de vistos y cooldowns
SEEN_STORE_PATH = os.getenv("SEEN_STORE_PATH", "seen_ids_imap.json")
_last_sent_at = {}        # chat_id -> ts
_last_code_sent_at = {}   # code   -> ts

# Telegram getUpdates offset
_updates_offset = 0

# ========= Utilidades =========
def _split_csv_env_val(raw: str) -> List[str]:
    return [x.strip().lower() for x in (raw or "").split(",") if x.strip()]

def parse_allowed() -> set[str]:
    raw = os.getenv("ALLOWED_CHAT_IDS", "")
    ids = [x.strip() for x in raw.split(",") if x.strip()]
    return set(ids)

def is_allowed(chat_id: int) -> bool:
    allowed = parse_allowed()
    if allowed:
        return str(chat_id) in allowed
    if CHAT_ID:
        return str(chat_id) == str(CHAT_ID)
    return True  # si no configuraste nada, permitimos (recomiendo llenar ALLOWED_CHAT_IDS)

def remove_invisibles(s: str) -> str:
    if not s: return ""
    invis = "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00a0\u202f"
    return "".join(ch for ch in s if ch not in invis)

def normalize_digits(s: str) -> str:
    if not s: return ""
    out = []
    for ch in s:
        try:
            if ch.isdigit():
                out.append(str(unicodedata.digit(ch)))
            else:
                out.append(ch)
        except Exception:
            out.append(ch)
    return "".join(out)

def match_required_subject(subject: str) -> bool:
    pats = REQUIRED_SUBJECT_PATTERNS.strip()
    if not pats:
        return True
    try:
        return re.search(pats, subject or "", re.IGNORECASE) is not None
    except re.error:
        return True

def sender_allowed(sender_header: str) -> bool:
    allowed = _split_csv_env_val(ALLOWED_SENDERS)
    if not allowed:
        return True
    try:
        addr = parseaddr(sender_header or "")[1].lower()
    except Exception:
        addr = (sender_header or "").lower()
    s = addr if addr else (sender_header or "").lower()
    # Para dominios, permite subdominios: *.spotify.com
    return any(
        s == dom or
        s.endswith(f"@{dom}") or
        s.endswith(f".{dom}")
        for dom in allowed
    )

def deny_code(code: str) -> bool:
    deny = set(_split_csv_env_val(DENY_CODE_VALUES))
    return code.lower() in deny

def should_send_code(code: str) -> bool:
    now = time.time()
    last = _last_code_sent_at.get(code, 0)
    if now - last < CODE_COOLDOWN_MIN * 60:
        return False
    _last_code_sent_at[code] = now
    return True

# ========= Telegram sending (mejor logging) =========
def send_telegram_to(chat_id: int, text: str) -> Tuple[int, str]:
    if not BOT_TOKEN:
        print("[TG] ERROR: BOT_TOKEN no configurado", flush=True)
        return (0, "no-token")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=15)
        txt = r.text or ""
        print(f"[TG SEND] chat={chat_id} status={r.status_code} resp={txt[:1000]}", flush=True)
        return (r.status_code, txt)
    except Exception as e:
        print(f"[TG SEND ERROR] chat={chat_id} exc={e}", flush=True)
        return (0, str(e))

def send_telegram_safe(chat_id: int, text: str, max_retries: int = 5) -> bool:
    now = time.time()
    last = _last_sent_at.get(chat_id, 0)
    wait = TG_MIN_INTERVAL_SEC - (now - last)
    if wait > 0:
        time.sleep(wait)

    for attempt in range(1, max_retries+1):
        status, resp = send_telegram_to(chat_id, text)
        if status == 200:
            _last_sent_at[chat_id] = time.time()
            return True
        # Log common Telegram errors
        if status in (401, 400, 403):
            # 401 = invalid token, 403 = bot blocked or chat inaccessible, 400 = bad request
            print(f"[TG] Fatal sending error (status={status}) resp={resp}", flush=True)
            return False
        if status == 429:
            try:
                data = json.loads(resp)
                retry_after = int((data.get("parameters", {}) or {}).get("retry_after", 1))
            except Exception:
                retry_after = 2
            sleep_for = max(2, retry_after + 1)
            print(f"[TG] Rate limited, sleeping {sleep_for}s", flush=True)
            time.sleep(sleep_for)
            continue
        # Other transient errors: small backoff
        print(f"[TG] attempt {attempt} failed status={status}, retrying...", flush=True)
        time.sleep(1 + attempt)
    return False

def broadcast_with_status(text: str) -> bool:
    ok = True
    targets = parse_allowed() or {str(CHAT_ID)} if CHAT_ID else parse_allowed()
    print(f"[TG BROADCAST] to={targets} text='{text}'", flush=True)
    for tid in targets:
        try:
            sent = send_telegram_safe(int(tid), text, max_retries=5)
            print(f"[TG BROADCAST RESULT] chat={tid} sent={sent}", flush=True)
            if not sent:
                ok = False
        except Exception as e:
            print(f"[TG BROADCAST EXC] chat={tid} err={e}", flush=True)
            ok = False
    return ok

# ========= Persistencia de vistos =========
def load_seen() -> set:
    try:
        with open(SEEN_STORE_PATH, "r") as f:
            data = json.load(f)
            return set(data if isinstance(data, list) else [])
    except Exception:
        return set()

def save_seen(seen_set: set):
    try:
        with open(SEEN_STORE_PATH, "w") as f:
            json.dump(list(seen_set), f)
    except Exception:
        pass

# ========= IMAP helpers (reutilizo tu lógica) =========
def connect_imap(host: str, port: int, user: str, password: str) -> imaplib.IMAP4_SSL:
    M = imaplib.IMAP4_SSL(host=host, port=port)
    M.login(user, password)
    return M

def fetch_recent_messages_ids(M: imaplib.IMAP4_SSL, since_dt: datetime) -> List[str]:
    if SEARCH_ALL:
        status, data = M.search(None, 'ALL')
    else:
        since_str = since_dt.strftime("%d-%b-%Y")  # formato inglés
        status, data = M.search(None, 'SINCE', since_str)
    if status != 'OK' or not data:
        return []
    ids = data[0].split()
    return [i.decode() for i in ids]

def _decode_header(hdr_val: str) -> str:
    parts = email.header.decode_header(hdr_val or "")
    out = []
    for s, enc in parts:
        if isinstance(s, bytes):
            try:
                out.append(s.decode(enc or "utf-8", errors="ignore"))
            except Exception:
                out.append(s.decode("utf-8", errors="ignore"))
        else:
            out.append(s or "")
    return "".join(out)

def read_email(M: imaplib.IMAP4_SSL, msg_id: str) -> Tuple[str, str, str, datetime]:
    status, data = M.fetch(msg_id, '(RFC822)')
    if status != 'OK' or not data or not data[0]:
        return "", "", "", datetime.now(timezone.utc)
    raw = data[0][1]
    msg = email.message_from_bytes(raw)

    # Fecha
    try:
        date_hdr = msg.get("Date")
        internal_date = email.utils.parsedate_to_datetime(date_hdr) if date_hdr else None
        if internal_date and internal_date.tzinfo is None:
            internal_date = internal_date.replace(tzinfo=timezone.utc)
        if not internal_date:
            internal_date = datetime.now(timezone.utc)
    except Exception:
        internal_date = datetime.now(timezone.utc)

    subject_txt = _decode_header(msg.get("Subject", ""))
    from_txt    = _decode_header(msg.get("From", ""))

    # Cuerpo
    body_txt = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp  = (part.get("Content-Disposition") or "").lower()
            if ctype.startswith("text/plain") and "attachment" not in disp:
                try:
                    body_txt += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
    else:
        try:
            body_txt = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
        except Exception:
            body_txt = msg.get_payload() if isinstance(msg.get_payload(), str) else ""

    return subject_txt, from_txt, body_txt, internal_date

# ========= Helper: buscar código en una cuenta (no marca como visto) =========
def get_latest_code_from_account(idx:int, host:str, port:int, user:str, pwd:str, folder:str, lookback_minutes:int=60) -> Optional[str]:
    try:
        M = connect_imap(host, port, user, pwd)
        try:
            M.select(folder)
        except Exception:
            try: M.logout()
            except: pass
            return None
        since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        ids = fetch_recent_messages_ids(M, since_dt=since)
        ids = ids[-200:]
        ids.reverse()
        for mid in ids:
            subject, from_hdr, body, ts = read_email(M, mid)
            if ts < since:
                continue
            if not sender_allowed(from_hdr):
                continue
            subj_clean = remove_invisibles(subject or "")
            subj_norm  = normalize_digits(subj_clean)
            # allow subject mismatch fallbacks to body
            cand = ASCII_CODE_RE.findall(subj_norm) or UNICODE_CODE_RE.findall(subj_norm)
            codes = []
            if cand:
                codes = [c for c in cand if len(c) == 6 and c.isdigit() and not deny_code(c)]
            elif ALLOW_BODY_FALLBACK == "1":
                body_clean = remove_invisibles(body or "")
                body_norm  = normalize_digits(body_clean)
                cand_b = ASCII_CODE_RE.findall(body_norm) or UNICODE_CODE_RE.findall(body_norm)
                for c in cand_b:
                    if len(c) == 6 and c.isdigit() and not deny_code(c) and c not in codes:
                        codes.append(c)
            if codes:
                try: M.logout()
                except: pass
                return codes[0]
        try: M.logout()
        except: pass
        return None
    except Exception as e:
        print(f"[ACC{idx}] get_latest_code error: {e}", flush=True)
        return None

# ========= Telegram getUpdates (comandos) =========
def tg_get_updates(offset: int) -> dict:
    if not BOT_TOKEN:
        return {"ok": False, "error": "no-token"}
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    try:
        r = requests.get(url, params={"timeout": 0, "offset": offset}, timeout=10)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def poll_commands_once(accounts_conf):
    global _updates_offset
    if not ENABLE_COMMANDS or not BOT_TOKEN:
        return
    data = tg_get_updates(_updates_offset)
    if not data.get("ok"):
        # could log: data.get("error")
        return
    for upd in data.get("result", []):
        _updates_offset = upd["update_id"] + 1
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        if not text or chat_id is None:
            continue
        if not is_allowed(chat_id):
            print(f"[CMD] chat {chat_id} not allowed", flush=True)
            continue
        low = text.lower()
        if low.startswith("/ping"):
            send_telegram_safe(chat_id, "pong ✅")
            continue
        if low.startswith("/codigo"):
            send_telegram_safe(chat_id, "Buscando tu código… ⏳")
            # intentar buscar en todas las cuentas hasta encontrar
            found = None
            for (idx, host, port, user, pwd, acc_name) in accounts_conf:
                folder = os.getenv(f"IMAP_FOLDER_{idx}", "INBOX")
                code = get_latest_code_from_account(idx, host, port, user, pwd, folder, lookback_minutes=LOOKBACK_MINUTES)
                if code:
                    found = f"[{acc_name}] {code}"
                    break
            if found:
                send_telegram_safe(chat_id, f"✅ {found}")
            else:
                send_telegram_safe(chat_id, "❌ No encontré un código reciente. Revisa remitente/asunto o reenvía el correo.")
            continue

# ========= MAIN =========
def main():
    if not BOT_TOKEN or not (CHAT_ID or os.getenv("ALLOWED_CHAT_IDS")):
        print("ERROR: Falta BOT_TOKEN o CHAT_ID/ALLOWED_CHAT_IDS", flush=True)
        time.sleep(60)
        return

    print("DEBUG: cuentas configuradas:", flush=True)
    accounts = []
    for i in range(1, MAX_ACCOUNTS + 1):
        host = os.getenv(f"IMAP_HOST_{i}")
        port = int(os.getenv(f"IMAP_PORT_{i}", "993"))
        user = os.getenv(f"IMAP_USER_{i}")
        pwd  = os.getenv(f"IMAP_PASS_{i}")
        if host and user and pwd:
            accounts.append((i, host, port, user, pwd, os.getenv(f"ACCOUNT{i}_NAME", f"Cuenta {i}")))
            print(f" - ACC{i}: {user}@{host}:{port}", flush=True)
    if not accounts:
        print("ERROR: No hay cuentas IMAP configuradas (IMAP_HOST_i / IMAP_USER_i / IMAP_PASS_i).", flush=True)
        time.sleep(60)
        return

    since = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
    seen = load_seen()
    print(f"Worker IMAP iniciado… SEARCH_ALL={'ON' if SEARCH_ALL else 'OFF'} DEBUG_LIST_ALL={'ON' if DEBUG_LIST_ALL else 'OFF'} ENABLE_COMMANDS={ENABLE_COMMANDS}", flush=True)

    # Mensaje de prueba al arrancar (útil para validar CHAT_ID/TOKEN)
    if CHAT_ID:
        try:
            send_telegram_safe(int(CHAT_ID), "✅ Bot IMAP conectado y listo (prueba de arranque).")
        except Exception as e:
            print("[TG START NOTICE ERROR]", e, flush=True)

    while True:
        try:
            # Pollear comandos (si está habilitado)
            if ENABLE_COMMANDS:
                poll_commands_once(accounts)

            # Escaneo normal
            for (idx, host, port, user, pwd, acc_name) in accounts:
                try:
                    M = connect_imap(host, port, user, pwd)

                    # Selecciona carpeta (por defecto INBOX; si quieres, usa IMAP_FOLDERS_i y un loop)
                    folder = os.getenv(f"IMAP_FOLDER_{idx}", "INBOX")
                    try:
                        M.select(folder)
                    except Exception:
                        print(f"[ACC{idx}] No se pudo abrir carpeta: {folder}", flush=True)
                        try:
                            M.logout()
                        except Exception:
                            pass
                        continue

                    if DEBUG_LIST_ALL:
                        # debug dump
                        try:
                            s, d = M.search(None, 'ALL')
                            if s == 'OK' and d and d[0]:
                                ids = [i.decode() for i in d[0].split()][-10:]
                                print(f"[ACC{idx}] debug tail ids: {ids}", flush=True)
                        except Exception:
                            pass

                    ids = fetch_recent_messages_ids(M, since_dt=since)
                    print(f"[ACC{idx}] ids encontrados: {len(ids)}", flush=True)

                    # Procesar los más recientes (tope por seguridad)
                    for mid in ids[-50:]:
                        key = f"{idx}:{folder}:{mid}"
                        if key in seen:
                            continue

                        subject, from_hdr, body, ts = read_email(M, mid)
                        if ts < since:
                            seen.add(key); save_seen(seen); continue

                        subj_clean = remove_invisibles(subject or "")
                        subj_norm  = normalize_digits(subj_clean)

                        parsed_from = parseaddr(from_hdr or "")[1].lower()
                        print(f"[ACC{idx}] FROM: {from_hdr!r} | parsed={parsed_from}", flush=True)

                        if not sender_allowed(from_hdr):
                            print(f"[ACC{idx}] DESCARTADO remitente: {from_hdr!r}", flush=True)
                            seen.add(key); save_seen(seen); continue

                        try:
                            matched = match_required_subject(subj_norm)
                        except Exception:
                            matched = True
                        print(f"[ACC{idx}] subject match? {matched} subj={subj_norm!r}", flush=True)
                        if not matched:
                            seen.add(key); save_seen(seen); continue

                        cand = ASCII_CODE_RE.findall(subj_norm)
                        if not cand:
                            cand = UNICODE_CODE_RE.findall(subj_norm)
                        print(f"[ACC{idx}] candidatas (subject): {cand}", flush=True)

                        codes = []
                        if cand:
                            codes = [c for c in cand if len(c) == 6 and c.isdigit() and not deny_code(c)]
                        elif ALLOW_BODY_FALLBACK == "1":
                            body_clean = remove_invisibles(body or "")
                            body_norm  = normalize_digits(body_clean)
                            cand_b = ASCII_CODE_RE.findall(body_norm) or UNICODE_CODE_RE.findall(body_norm)
                            print(f"[ACC{idx}] candidatas (body): {cand_b}", flush=True)
                            for c in cand_b:
                                if len(c) == 6 and c.isdigit() and not deny_code(c) and c not in codes:
                                    codes.append(c)

                        if codes:
                            code = codes[0]
                            if CODE_COOLDOWN_MIN == 0 or should_send_code(code):
                                ok = broadcast_with_status(f"[{acc_name}] {code}")
                                print(f"[ACC{idx}] enviado? {ok}", flush=True)
                            else:
                                print(f"[ACC{idx}] BLOQUEADO cooldown: {code}", flush=True)
                        else:
                            print(f"[ACC{idx}] SIN CÓDIGOS válidos", flush=True)

                        seen.add(key); save_seen(seen)

                    try:
                        M.logout()
                    except Exception:
                        pass

                except imaplib.IMAP4.error as e:
                    print(f"[ACC{idx}] IMAP ERROR: {e}", flush=True)
                except Exception as e:
                    print(f"[ACC{idx}] ERROR: {e}", flush=True)
                    print(traceback.format_exc(), flush=True)

        except Exception as e:
            print("[LOOP ERROR]", e, flush=True)
            print(traceback.format_exc(), flush=True)

        time.sleep(POLL_EVERY)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FATAL]", e, flush=True)
        print(traceback.format_exc(), flush=True)
        time.sleep(60)
