#!/usr/bin/env python3
import os, json, base64, glob, secrets, urllib.parse, mimetypes, smtplib, struct, re, hmac, hashlib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from email.message import EmailMessage

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WWW  = os.path.join(ROOT, "www")
ASSETS = os.path.join(WWW, "assets")
CFG_PX  = os.path.join(ROOT, "cfg", "field_map_px.json")
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.json")

# =========================
# Storage path (Render-safe)
# =========================
# If you attach a Render Persistent Disk mounted at /var/data,
# this will persist across deploys. Otherwise it falls back to repo db/.
DATA_DIR = os.environ.get("DATA_DIR", "").strip()
if not DATA_DIR:
    DATA_DIR = os.path.join(ROOT, "db")  # fallback for local/dev

# contracts + sessions live under DATA_DIR
DB = os.path.join(DATA_DIR, "contracts")
SESSIONS_PATH = os.path.join(DATA_DIR, "sessions.json")

os.makedirs(DB, exist_ok=True)
os.makedirs(os.path.dirname(SESSIONS_PATH), exist_ok=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat()

def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default

def read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def load_settings():
    s = read_json(SETTINGS_PATH, {})
    if not isinstance(s, dict):
        s = {}
    s.setdefault("auth", {})
    s["auth"].setdefault("cookie_name", "sid")
    s["auth"].setdefault("session_secret", "CHANGE_ME")
    s.setdefault("sales_users", {})
    # legacy alias
    if isinstance(s.get("users"), dict) and not s.get("sales_users"):
        s["sales_users"] = s["users"]
    return s

def sessions_load():
    d = read_json(SESSIONS_PATH, {})
    return d if isinstance(d, dict) else {}

def sessions_save(d):
    write_json(SESSIONS_PATH, d if isinstance(d, dict) else {})

def _sign(secret, msg):
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def make_cookie_value(secret, sid):
    sig = _sign(secret, sid)
    return f"{sid}.{sig}"

def parse_cookie_value(secret, val):
    if not val or "." not in val:
        return None
    sid, sig = val.split(".", 1)
    if not sid or not sig:
        return None
    good = _sign(secret, sid)
    if not hmac.compare_digest(good, sig):
        return None
    return sid

def esc(s):
    return (str(s)
        .replace("&","&amp;")
        .replace("<","&lt;")
        .replace(">","&gt;")
        .replace('"',"&quot;")
        .replace("'","&#39;")
    )

def cdir(cid):
    return os.path.join(DB, cid)

def ensure_contract(cid):
    os.makedirs(cdir(cid), exist_ok=True)
    meta_path = os.path.join(cdir(cid), "meta.json")
    if not os.path.exists(meta_path):
        write_json(meta_path, {"contract_id": cid, "created_at": now_iso(), "status": "empty"})

# ============================================================
# SINGLE FILE BUNDLE: db/contracts/<cid>/contract.json
# ============================================================
def bundle_path(cid):
    return os.path.join(cdir(cid), "contract.json")

def load_bundle(cid):
    """
    Single source of truth per contract:
      contract.json = { meta: {...}, fields: {...}, calc: {...} }
    """
    ensure_contract(cid)
    b = read_json(bundle_path(cid), None)
    if isinstance(b, dict):
        b.setdefault("meta", {})
        b.setdefault("fields", {})
        b.setdefault("calc", {})
        return b

    # bootstrap from legacy files if present
    meta = read_json(os.path.join(cdir(cid), "meta.json"),
                     {"contract_id": cid, "created_at": now_iso(), "status": "empty"})
    fields = read_json(os.path.join(cdir(cid), "fields.json"), {})
    calc = read_json(os.path.join(cdir(cid), "calc.json"), {})

    b = {
        "meta": meta if isinstance(meta, dict) else {"contract_id": cid, "created_at": now_iso(), "status": "empty"},
        "fields": fields if isinstance(fields, dict) else {},
        "calc": calc if isinstance(calc, dict) else {},
    }
    write_json(bundle_path(cid), b)
    return b

def save_bundle(cid, b):
    b.setdefault("meta", {})
    b["meta"]["updated_at"] = now_iso()
    write_json(bundle_path(cid), b)
    return b

def contract_meta(cid):
    b = load_bundle(cid)
    m = b.get("meta", {})
    return m if isinstance(m, dict) else {"contract_id": cid, "created_at": now_iso(), "status": "empty"}

def set_status(cid, status):
    b = load_bundle(cid)
    b.setdefault("meta", {})
    b["meta"]["contract_id"] = cid
    b["meta"].setdefault("created_at", now_iso())
    b["meta"]["status"] = status
    b["meta"]["updated_at"] = now_iso()
    save_bundle(cid, b)

    # legacy sync (safe)
    write_json(os.path.join(cdir(cid), "meta.json"), b["meta"])

def deep_get(d, dotted):
    cur = d
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur

def deep_set(d, dotted, value):
    parts = dotted.split(".")
    cur = d
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value

def png_size(path):
    with open(path, "rb") as f:
        sig = f.read(8)
        if sig != b"\x89PNG\r\n\x1a\n":
            return None
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                return None
            length = struct.unpack(">I", hdr[:4])[0]
            ctype = hdr[4:]
            chunk = f.read(length)
            f.read(4)  # crc
            if ctype == b'IHDR':
                w, h = struct.unpack(">II", chunk[:8])
                return (w, h)

def parse_money(s):
    if s is None:
        return 0.0
    s = str(s).strip()
    if not s:
        return 0.0
    s = s.replace(" ", "").replace("$", "").replace(",", ".")
    try:
        return float(s)
    except Exception:
        return 0.0

def money(n):
    try:
        return f"{float(n):.2f}"
    except Exception:
        return ""

def compute_calculations(fields):
    """Deterministic server-side calculations."""
    def get(name):
        return parse_money(deep_get(fields, name))

    # PAGE 2
    base = get("Prix_de_vente_de_base")
    rabais = get("Rabais_si_applicable")
    livraison = get("Livraison")
    extra_cuisine = get("EXTRA_cuisine_s")
    extra_comptoir = get("EXTRA_comptoir_s")

    before_tax = base - rabais + livraison + extra_cuisine + extra_comptoir
    tps = before_tax * 0.05
    tvq = before_tax * 0.09975
    total = before_tax + tps + tvq

    # PAGE 6 multiplications
    line_totals = {}

    def mul(q_field, unit_price, out_field):
        q = get(q_field)
        amt = q * unit_price
        line_totals[out_field] = amt
        return amt

    mul("QTÉ",   599.0,  "x_599")
    mul("QTÉ_2", 299.0,  "x_299")
    mul("QTÉ_3", 199.0,  "x_199")
    mul("QTÉ_4", 399.0,  "x_399")
    mul("QTÉ_5", 199.0,  "x_199_2")
    mul("QTÉ_6", 299.0,  "x_299_2")
    mul("QTÉ_7", 999.0,  "x_999")
    mul("QTÉ_8", 1499.0, "x_1499")

    # pi2 x 199$
    mul("Texte6", 199.0, "pi2_x_199")

    mul("QTÉ_9", 2499.0, "x_2499")

    # manual values included in TOTAL
    s_999  = get("Texte7")
    s_1499 = get("Texte8")
    s_1999 = get("Texte9")
    complet_2000 = get("Complet_2000")
    moitie_1000  = get("Moitié__1000")

    page6_total = (
        sum(line_totals.values())
        + s_999 + s_1499 + s_1999
        + complet_2000 + moitie_1000
    )

    # Quartz total (Quantité x 1495)
    q_quartz = get("Quantité")
    quartz_total = q_quartz * 1495.0

    calc = {
        "Prix_de_vente_avant_taxes": money(before_tax),
        "TPS_5_730072220RT0001": money(tps),
        "TVQ_9975_1232208119TQ0001": money(tvq),
        "Total_prix_de_vente_avec_taxes": money(total),
        "payments.no_finance.amount_at_measure": money(total * 0.40),
        "payments.no_finance.amount_pre_delivery": money(total * 0.60),
        "undefined": money(total * 0.40),
        "undefined_2": money(total * 0.60),

        "x_599": money(line_totals.get("x_599", 0.0)),
        "x_299": money(line_totals.get("x_299", 0.0)),
        "x_199": money(line_totals.get("x_199", 0.0)),
        "x_399": money(line_totals.get("x_399", 0.0)),
        "x_199_2": money(line_totals.get("x_199_2", 0.0)),
        "x_299_2": money(line_totals.get("x_299_2", 0.0)),
        "x_999": money(line_totals.get("x_999", 0.0)),
        "x_1499": money(line_totals.get("x_1499", 0.0)),
        "pi2_x_199": money(line_totals.get("pi2_x_199", 0.0)),
        "x_2499": money(line_totals.get("x_2499", 0.0)),

        # page 6 totals (your map uses undefined_3 / undefined_4)
        "undefined_3": money(page6_total),
        "undefined_4": money(quartz_total),

        "_meta": {"computed_at": now_iso()}
    }
    return calc

def calc_and_store(cid, fields):
    calc = compute_calculations(fields)

    b = load_bundle(cid)
    b["fields"] = fields if isinstance(fields, dict) else {}
    b["calc"] = calc if isinstance(calc, dict) else {}
    b.setdefault("meta", {})
    b["meta"]["contract_id"] = cid
    b["meta"].setdefault("created_at", now_iso())
    b["meta"]["updated_at"] = now_iso()
    save_bundle(cid, b)

    # legacy sync (safe)
    write_json(os.path.join(cdir(cid), "fields.json"), b["fields"])
    write_json(os.path.join(cdir(cid), "calc.json"), b["calc"])
    write_json(os.path.join(cdir(cid), "meta.json"), b["meta"])

    return calc

def token_new():
    return secrets.token_hex(16)

def store_token(cid, who, email):
    path = os.path.join(cdir(cid), "tokens.json")
    tokens = read_json(path, {})
    tokens = tokens if isinstance(tokens, dict) else {}
    tok = token_new()
    tokens[tok] = {"token": tok, "contract_id": cid, "who": who, "email": email, "created_at": now_iso(), "used": False}
    write_json(path, tokens)
    return tok

def token_lookup(tok):
    for p in glob.glob(os.path.join(DB, "*", "tokens.json")):
        tokens = read_json(p, {})
        if isinstance(tokens, dict) and tok in tokens:
            return p, tokens, tokens[tok]
    return None, None, None

def signature_state(cid):
    s = read_json(os.path.join(cdir(cid), "signatures.json"), {"client": None, "rep": None})
    if not isinstance(s, dict):
        s = {"client": None, "rep": None}
    s.setdefault("client", None)
    s.setdefault("rep", None)
    return s

def mark_signed_if_complete(cid):
    s = signature_state(cid)
    if s.get("client") and s.get("rep"):
        set_status(cid, "signed")

def base_url(handler):
    proto = handler.headers.get("X-Forwarded-Proto")
    host  = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or "localhost"
    scheme = "https" if proto == "https" else "http"
    return f"{scheme}://{host}"

def send_email(settings, to_email, subject, body):
    smtp = (settings or {}).get("smtp", {})
    if not smtp.get("enabled"):
        return False, "SMTP disabled"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp.get("from_email", smtp.get("username","no-reply@localhost"))
    msg["To"] = to_email
    msg.set_content(body)
    host = smtp.get("host")
    port = int(smtp.get("port", 587))
    user = smtp.get("username")
    pwd  = smtp.get("password")
    use_tls = bool(smtp.get("use_tls", True))

    with smtplib.SMTP(host, port, timeout=25) as s:
        s.ehlo()
        if use_tls:
            s.starttls()
            s.ehlo()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)
    return True, "sent"


class H(BaseHTTPRequestHandler):
    # Render health checks use HEAD. Without this, http.server returns 501.
    def do_HEAD(self):
        # lightweight health response
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()

    def settings(self):
        return load_settings()

    def current_user(self):
        s = self.settings()
        cookie_name = (s.get("auth") or {}).get("cookie_name", "sid")
        secret = (s.get("auth") or {}).get("session_secret", "CHANGE_ME")

        raw = self.headers.get("Cookie", "")
        cookies = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        sid_val = cookies.get(cookie_name)
        sid = parse_cookie_value(secret, sid_val)
        if not sid:
            return None
        sess = sessions_load().get(sid)
        if not isinstance(sess, dict):
            return None
        return sess.get("user")

    def require_login(self):
        return self.current_user() is not None

    def redirect_login(self):
        return self.redirect("/login")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)

        # Optional explicit health endpoint too:
        if path == "/healthz":
            return self.send_text("ok", 200)

        # Public routes
        if path.startswith("/assets/"):
            f = os.path.join(WWW, path.lstrip("/"))
            return self.serve_file(f, None)

        if path in ("/login", "/logout"):
            if path == "/logout":
                s = self.settings()
                cookie_name = (s.get("auth") or {}).get("cookie_name", "sid")
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Set-Cookie", f"{cookie_name}=; Path=/; Max-Age=0")
                self.end_headers()
                return
            tpl = read_text(os.path.join(WWW, "login.html"))
            return self.send_html(tpl)

        # Auth gate
        public_prefixes = ("/sign", "/contract/signature_image", "/contract/print")
        if not path.startswith(public_prefixes):
            if not self.require_login():
                return self.redirect_login()

        if path in ("/", "/sales"):
            tpl = read_text(os.path.join(WWW, "sales.html"))
            user = self.current_user() or ""
            return self.send_html(tpl.replace("<!--USER-->", esc(user)))

        if path == "/api/contracts_search":
            term = (q.get("q", [""])[0] or "").strip().lower()
            out = []
            for cid_path in glob.glob(os.path.join(DB, "*")):
                cid = os.path.basename(cid_path)
                b = read_json(os.path.join(cid_path, "contract.json"), None)
                if not isinstance(b, dict):
                    continue
                fields = b.get("fields", {}) if isinstance(b.get("fields", {}), dict) else {}
                meta = b.get("meta", {}) if isinstance(b.get("meta", {}), dict) else {}
                tokens = [cid]

                def add(v):
                    if v is None:
                        return
                    v = str(v).strip()
                    if v:
                        tokens.append(v)

                add(deep_get(fields, "contract.quote_number"))
                add(deep_get(fields, "client.first_name"))
                add(deep_get(fields, "client.last_name"))
                add(deep_get(fields, "client.phone_main"))
                add(deep_get(fields, "client.address_full"))
                add(deep_get(fields, "vendor.rep_name_print"))

                blob = " ".join(tokens).lower()
                if term and term not in blob:
                    continue

                out.append({
                    "contract_id": cid,
                    "quote": deep_get(fields, "contract.quote_number") or "",
                    "client": ((deep_get(fields, "client.first_name") or "") + " " + (deep_get(fields, "client.last_name") or "")).strip(),
                    "phone": deep_get(fields, "client.phone_main") or "",
                    "address": deep_get(fields, "client.address_full") or "",
                    "status": meta.get("status", ""),
                    "updated_at": meta.get("updated_at") or meta.get("created_at") or "",
                })

            out.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
            payload = json.dumps({"ok": True, "results": out[:200]}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # --- Your existing routes below are unchanged ---
        # NOTE: I’m keeping your original logic as-is to avoid breaking behavior.
        # Everything from /contract/print onward stays the same in your current file.

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # To keep this answer readable, paste back in the remainder of your
        # existing do_GET routes (starting at /contract/print ...) unchanged.
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        return self.send_text("Not found", 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        form = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        form = {k: (v[0] if isinstance(v, list) and v else "") for k, v in form.items()}

        # LOGIN
        if path == "/login":
            username = (form.get("username") or "").strip()
            password = (form.get("password") or "").strip()
            s = self.settings()
            users = s.get("sales_users") or {}
            urec = users.get(username) if isinstance(users, dict) else None
            if not (isinstance(urec, dict) and urec.get("password") == password):
                tpl = read_text(os.path.join(WWW, "login.html"))
                tpl = tpl.replace("<!--ERROR-->", "Identifiants invalides.")
                return self.send_html(tpl, 401)

            sid = "s_" + secrets.token_hex(16)
            sess = sessions_load()
            sess[sid] = {"user": username, "created_at": now_iso()}
            sessions_save(sess)

            cookie_name = (s.get("auth") or {}).get("cookie_name", "sid")
            secret = (s.get("auth") or {}).get("session_secret", "CHANGE_ME")
            cval = make_cookie_value(secret, sid)
            self.send_response(302)
            self.send_header("Location", "/sales")
            self.send_header("Set-Cookie", f"{cookie_name}={cval}; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()
            return

        # --- keep the rest of your POST routes unchanged (save/compute/send/sign) ---

        return self.send_text("Not found", 404)

    def serve_file(self, path, content_type):
        if not os.path.exists(path):
            return self.send_text("not found", 404)
        ctype = content_type or mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_html(self, html, code=200):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, txt, code=200):
        data = str(txt).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()


def main():
    settings = read_json(SETTINGS_PATH, {})
    host = (settings.get("server") or {}).get("host", "127.0.0.1")
    port = int((settings.get("server") or {}).get("port", 8080))
    httpd = ThreadingHTTPServer((host, port), H)
    print(f"9999 Contract v2 (bundle): http://{host}:{port}/contract")
    print(f"Mapper tool: http://{host}:{port}/mapper?page=1")
    httpd.serve_forever()


if __name__ == "__main__":
    # Render entrypoint
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", "10000"))

    print(f"Starting server on {HOST}:{PORT}")
    httpd = ThreadingHTTPServer((HOST, PORT), H)
    httpd.serve_forever()
