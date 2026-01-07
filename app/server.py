#!/usr/bin/env python3
import os, json, base64, glob, secrets, urllib.parse, mimetypes, smtplib, struct, hmac, hashlib, traceback
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from email.message import EmailMessage

# -------------------------
# Paths
# -------------------------
# If server.py is in /app, ROOT becomes repo root.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

WWW    = os.path.join(ROOT, "www")
ASSETS = os.path.join(WWW, "assets")
CFG_PX = os.path.join(ROOT, "cfg", "field_map_px.json")

DB = os.path.join(ROOT, "db", "contracts")
os.makedirs(DB, exist_ok=True)

# Sessions (note: Render disk can be ephemeral depending on your plan)
SESSIONS_PATH = os.path.join(ROOT, "db", "sessions.json")
os.makedirs(os.path.dirname(SESSIONS_PATH), exist_ok=True)

# Settings: try multiple locations
SETTINGS_CANDIDATES = [
    os.path.join(ROOT, "settings.json"),                      # repo root (recommended)
    os.path.join(os.path.dirname(__file__), "settings.json"), # alongside server.py (/app/settings.json)
]

# -------------------------
# Helpers
# -------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default

def read_json(path, default):
    if not path or not os.path.exists(path):
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

def find_settings_path():
    # allow explicit override on Render
    env_path = os.environ.get("SETTINGS_PATH", "").strip()
    if env_path and os.path.exists(env_path):
        return env_path
    for p in SETTINGS_CANDIDATES:
        if os.path.exists(p):
            return p
    return None

def load_settings():
    p = find_settings_path()
    s = read_json(p, {}) if p else {}
    if not isinstance(s, dict):
        s = {}

    # auth defaults
    s.setdefault("auth", {})
    s["auth"].setdefault("cookie_name", "sid")
    s["auth"]["session_secret"] = (
        os.environ.get("SESSION_SECRET")
        or s["auth"].get("session_secret")
        or "CHANGE_ME"
    )

    # users: settings.json OR env
    s.setdefault("sales_users", {})
    if isinstance(s.get("users"), dict) and not s.get("sales_users"):
        s["sales_users"] = s["users"]

    env_user = os.environ.get("SALES_USER", "").strip()
    env_pass = os.environ.get("SALES_PASS", "").strip()
    if env_user and env_pass:
        s["sales_users"][env_user] = {"password": env_pass}

    # smtp optional (kept for future), but NEVER required
    s.setdefault("smtp", {})
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

def qr_url(data, size=260):
    # External QR render (no python libs)
    return "https://api.qrserver.com/v1/create-qr-code/?size={0}x{0}&data={1}".format(
        int(size),
        urllib.parse.quote(data, safe="")
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
    ensure_contract(cid)
    b = read_json(bundle_path(cid), None)
    if isinstance(b, dict):
        b.setdefault("meta", {})
        b.setdefault("fields", {})
        b.setdefault("calc", {})
        return b

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

def set_status(cid, status):
    b = load_bundle(cid)
    b.setdefault("meta", {})
    b["meta"]["contract_id"] = cid
    b["meta"].setdefault("created_at", now_iso())
    b["meta"]["status"] = status
    b["meta"]["updated_at"] = now_iso()
    save_bundle(cid, b)
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
            f.read(4)
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
    def get(name):
        return parse_money(deep_get(fields, name))

    base = get("Prix_de_vente_de_base")
    rabais = get("Rabais_si_applicable")
    livraison = get("Livraison")
    extra_cuisine = get("EXTRA_cuisine_s")
    extra_comptoir = get("EXTRA_comptoir_s")

    before_tax = base - rabais + livraison + extra_cuisine + extra_comptoir
    tps = before_tax * 0.05
    tvq = before_tax * 0.09975
    total = before_tax + tps + tvq

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
    mul("Texte6", 199.0, "pi2_x_199")
    mul("QTÉ_9", 2499.0, "x_2499")

    s_999  = get("Texte7")
    s_1499 = get("Texte8")
    s_1999 = get("Texte9")
    complet_2000 = get("Complet_2000")
    moitie_1000  = get("Moitié__1000")

    page6_total = sum(line_totals.values()) + s_999 + s_1499 + s_1999 + complet_2000 + moitie_1000
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
    has_client = bool(s.get("client"))
    has_rep = bool(s.get("rep"))
    if has_client and has_rep:
        set_status(cid, "signed")
    elif has_client:
        set_status(cid, "signed_client")
    elif has_rep:
        set_status(cid, "signed_rep")

def base_url(handler):
    proto = handler.headers.get("X-Forwarded-Proto")
    host  = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or "localhost"
    scheme = "https" if proto == "https" else "http"
    return f"{scheme}://{host}"

def send_email(settings, to_email, subject, body):
    """
    Best-effort SMTP. NEVER crash request.
    Returns (ok: bool, msg: str)
    """
    try:
        smtp = (settings or {}).get("smtp", {})
        if not smtp.get("enabled"):
            return False, "SMTP disabled"

        host = (smtp.get("host") or "").strip()
        if not host:
            return False, "SMTP host missing"

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = (smtp.get("from_email") or smtp.get("username") or "no-reply@localhost").strip()
        msg["To"] = to_email
        msg.set_content(body)

        port = int(smtp.get("port", 587))
        user = (smtp.get("username") or "").strip()
        pwd  = (smtp.get("password") or "").strip()
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
    except Exception as e:
        return False, f"SMTP error: {e}"

# -------------------------
# HTTP Handler
# -------------------------
class H(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_exception(self):
        traceback.print_exc()

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
        try:
            u = urllib.parse.urlparse(self.path)
            path = u.path
            q = urllib.parse.parse_qs(u.query)

            # alias
            if path == "/contracts":
                return self.redirect("/contract" + (("?" + u.query) if u.query else ""))

            # static
            if path.startswith("/assets/"):
                f = os.path.join(WWW, path.lstrip("/"))
                return self.serve_file(f, None)

            # auth pages
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
                st = self.settings()
                if not (st.get("sales_users") or {}):
                    tpl = tpl.replace("<!--ERROR-->", "⚠️ Aucun utilisateur configuré. Ajoute SALES_USER / SALES_PASS sur Render.")
                return self.send_html(tpl)

            # public routes
            public_prefixes = ("/sign", "/contract/signature_image", "/contract/print")
            if not path.startswith(public_prefixes):
                if not self.require_login():
                    return self.redirect_login()

            if path in ("/", "/sales"):
                tpl = read_text(os.path.join(WWW, "sales.html"))
                user = self.current_user() or ""
                return self.send_html(tpl.replace("<!--USER-->", esc(user)))

            # SEND PAGE
            if path == "/contract/send":
                cid = q.get("id", [""])[0]
                if not cid:
                    return self.send_text("missing id", 400)
                ensure_contract(cid)

                html = f"""<!doctype html><html lang='fr'><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Envoyer — {esc(cid)}</title>
<style>
body{{margin:0;font-family:system-ui;background:#0b0f19;color:#e5e7eb}}
.top{{padding:12px 14px;background:rgba(17,24,39,.9);border-bottom:1px solid rgba(255,255,255,.10);display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.btn{{border:1px solid rgba(255,255,255,.10);border-radius:12px;padding:9px 12px;background:#f5c542;color:#111;font-weight:900;text-decoration:none;cursor:pointer}}
.btn.secondary{{background:rgba(15,23,42,.80);color:#e5e7eb}}
.card{{max-width:760px;margin:18px auto;padding:14px;border:1px solid rgba(255,255,255,.10);border-radius:16px;background:rgba(15,23,42,.60)}}
input{{width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.10);background:rgba(15,23,42,.80);color:#e5e7eb}}
label{{font-weight:900;font-size:13px}}
.hint{{font-size:12px;opacity:.85}}
code{{background:rgba(0,0,0,.25);padding:2px 6px;border-radius:8px}}
</style></head><body>
<div class='top'>
  <a class='btn secondary' href='/contract?id={urllib.parse.quote(cid)}'>Retour</a>
  <div style='font-weight:900'>Envoyer pour signature — {esc(cid)}</div>
</div>
<div class='card'>
  <form method='POST' action='/contract/send'>
    <input type='hidden' name='contract_id' value='{esc(cid)}'>
    <label>Email du client</label><br><input name='client_email' type='email' required><br><br>
    <label>Email du représentant</label><br><input name='rep_email' type='email' required><br><br>
    <button class='btn' type='submit'>Générer les liens</button>
  </form>
  <p class='hint'>
    Pas besoin d’email pour tester. L’app génère les liens + QR et les enregistre dans
    <code>db/contracts/{esc(cid)}/email_log.json</code>.
  </p>
</div>
</body></html>"""
                return self.send_html(html)

            # signature image (public)
            if path == "/contract/signature_image":
                cid = q.get("id", [""])[0]
                who = q.get("who", [""])[0]
                if not cid or who not in ("client", "rep"):
                    return self.send_text("bad request", 400)
                sigs = signature_state(cid)
                rec = sigs.get(who) or {}
                png_path = rec.get("png_path")
                if not png_path or not os.path.exists(png_path):
                    return self.send_text("not found", 404)
                return self.serve_file(png_path, "image/png")

            # sign flow (public)
            if path == "/sign":
                token = q.get("token", [""])[0]
                if not token:
                    return self.send_text("missing token", 400)
                tp, all_tokens, rec = token_lookup(token)
                if not rec:
                    return self.send_text("token invalid", 404)
                if rec.get("used"):
                    return self.send_text("Lien déjà utilisé.", 200)

                cid = rec["contract_id"]
                who = rec["who"]
                label = "Client" if who == "client" else "Représentant"

                cfg = read_json(CFG_PX, {"signature_zones": []})
                sig_map = cfg.get("signature_zones", []) if isinstance(cfg, dict) else []
                zones = [z for z in sig_map if z.get("who") == who]

                tpl = read_text(os.path.join(WWW, "sign_flow.html"))
                payload = json.dumps({
                    "token": token,
                    "contract_id": cid,
                    "who": who,
                    "label": label,
                    "zones": zones,
                }, ensure_ascii=False)
                return self.send_html(tpl.replace("<!--PAYLOAD-->", esc(payload)))

            if path == "/sign/done":
                cid = q.get("cid", [""])[0]
                if not cid:
                    return self.send_text("missing cid", 400)
                html = f"""<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Merci</title>
<style>
body{{margin:0;font-family:system-ui;background:#0b0f19;color:#e5e7eb}}
.wrap{{max-width:840px;margin:40px auto;padding:0 16px}}
.card{{background:rgba(15,23,42,.65);border:1px solid rgba(255,255,255,.12);border-radius:18px;padding:18px}}
.btn{{display:inline-block;margin-top:14px;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:10px 14px;background:#f5c542;color:#111;font-weight:900;text-decoration:none}}
.btn.secondary{{background:rgba(15,23,42,.85);color:#e5e7eb}}
</style></head><body>
<div class='wrap'>
  <div class='card'>
    <h2 style='margin:0 0 8px 0'>Signature enregistrée ✅</h2>
    <p style='margin:0 0 10px 0'>Tu peux maintenant revenir au contrat. (PDF imprimable si tu as /contract/print dans ton repo.)</p>
    <a class='btn secondary' href='/contract?id={urllib.parse.quote(cid)}'>Retour au contrat</a>
  </div>
</div>
</body></html>"""
                return self.send_html(html)

            # contract view (minimal – relies on www/contract.html existing)
            if path == "/contract":
                cid = q.get("id", [None])[0] or ("c_" + secrets.token_hex(8))
                ensure_contract(cid)

                b = load_bundle(cid)
                status = (b.get("meta", {}) or {}).get("status", "empty")

                tpl = read_text(os.path.join(WWW, "contract.html"))
                # If your contract.html expects placeholders, keep your existing template behavior.
                # This minimal response just ensures route exists.
                if "<!--TOPBAR-->" in tpl:
                    topbar = (
                        f"<div class='topbar'>"
                        f"<div class='brand'>9999 — Contrat</div>"
                        f"<div class='pill'>Statut: <b id='status'>{esc(status)}</b></div>"
                        f"<input type='hidden' name='contract_id' value='{esc(cid)}'>"
                        f"<button class='btn' type='submit'>Sauvegarder &amp; Calculer</button>"
                        f"<a class='btn secondary' href='/contract/send?id={urllib.parse.quote(cid)}'>Envoyer</a>"
                        f"</div>"
                    )
                    tpl = tpl.replace("<!--TOPBAR-->", topbar)
                return self.send_html(tpl)

            return self.send_text("Not found", 404)

        except Exception:
            self.log_exception()
            return self.send_text("Server error (see logs).", 500)

    def do_POST(self):
        try:
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

            # SEND (generate links + QR; SMTP optional)
            if path == "/contract/send":
                cid = (form.get("contract_id") or "").strip()
                client_email = (form.get("client_email") or "").strip()
                rep_email = (form.get("rep_email") or "").strip()
                if not cid or not client_email or not rep_email:
                    return self.send_text("missing", 400)

                ensure_contract(cid)
                set_status(cid, "to_sign")

                t_client = store_token(cid, "client", client_email)
                t_rep = store_token(cid, "rep", rep_email)

                settings = load_settings()
                base = base_url(self)
                link_client = f"{base}/sign?token={t_client}"
                link_rep = f"{base}/sign?token={t_rep}"

                subject = "Signature requise — Contrat Cuisines 9999"
                ok1, msg1 = send_email(settings, client_email, subject,
                    f"Bonjour,\n\nVeuillez signer le contrat via ce lien:\n{link_client}\n\nMerci,\nCuisines 9999\n")
                ok2, msg2 = send_email(settings, rep_email, subject,
                    f"Bonjour,\n\nVeuillez signer (représentant) via ce lien:\n{link_rep}\n\nMerci,\nCuisines 9999\n")

                write_json(os.path.join(cdir(cid), "email_log.json"), {
                    "sent_at": now_iso(),
                    "client_email": client_email,
                    "rep_email": rep_email,
                    "client_link": link_client,
                    "rep_link": link_rep,
                    "smtp_client": {"ok": ok1, "msg": msg1},
                    "smtp_rep": {"ok": ok2, "msg": msg2},
                })

                client_qr = qr_url(link_client)
                rep_qr = qr_url(link_rep)

                html = f"""<!doctype html><html lang='fr'><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Liens générés — {esc(cid)}</title>
<style>
body{{margin:0;font-family:system-ui;background:#0b0f19;color:#e5e7eb}}
.wrap{{max-width:980px;margin:26px auto;padding:0 16px}}
.card{{background:rgba(15,23,42,.65);border:1px solid rgba(255,255,255,.12);border-radius:18px;padding:18px}}
.btn{{display:inline-block;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:10px 14px;background:#f5c542;color:#111;font-weight:900;text-decoration:none;cursor:pointer}}
.btn.secondary{{background:rgba(15,23,42,.85);color:#e5e7eb}}
.grid{{display:grid;grid-template-columns:1fr;gap:14px;margin-top:14px}}
@media(min-width:860px){{.grid{{grid-template-columns:1fr 1fr}}}}
.box{{padding:12px;border-radius:16px;border:1px solid rgba(255,255,255,.10);background:rgba(0,0,0,.20)}}
.small{{font-size:12px;opacity:.85}}
code{{display:block;word-break:break-all;background:rgba(0,0,0,.25);padding:8px 10px;border-radius:12px;margin-top:8px}}
.rowbtns{{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}}
.qr{{display:none;margin-top:10px;padding:10px;border-radius:16px;border:1px solid rgba(255,255,255,.10);background:rgba(0,0,0,.18)}}
.qr img{{width:260px;height:260px;display:block;border-radius:12px;background:#fff}}
hr{{border:0;border-top:1px solid rgba(255,255,255,.10);margin:14px 0}}
</style>
</head><body>
<div class='wrap'>
  <div class='card'>
    <h2 style='margin:0 0 6px 0'>Liens de signature générés ✅</h2>
    <div class='small'>Contrat: <b>{esc(cid)}</b> — Statut: <b>to_sign</b></div>
    <div class='small'>SMTP: Client: {esc(msg1)} | Rep: {esc(msg2)}</div>

    <div class='grid'>
      <div class='box'>
        <div style='font-weight:900;font-size:16px'>Client</div>
        <div class='small'>Email: {esc(client_email)}</div>
        <code id='link_client'>{esc(link_client)}</code>

        <div class='rowbtns'>
          <button class='btn secondary' type='button' onclick="copyText('link_client')">Copier</button>
          <a class='btn secondary' href='{esc(link_client)}' target='_blank' rel='noopener'>Ouvrir</a>
          <button class='btn' type='button' onclick="toggleQR('qr_client')">Afficher QR</button>
        </div>

        <div class='qr' id='qr_client'>
          <div class='small' style='margin-bottom:8px'>Scanne avec ton téléphone</div>
          <img src='{esc(client_qr)}' alt='QR Client'>
        </div>
      </div>

      <div class='box'>
        <div style='font-weight:900;font-size:16px'>Représentant</div>
        <div class='small'>Email: {esc(rep_email)}</div>
        <code id='link_rep'>{esc(link_rep)}</code>

        <div class='rowbtns'>
          <button class='btn secondary' type='button' onclick="copyText('link_rep')">Copier</button>
          <a class='btn secondary' href='{esc(link_rep)}' target='_blank' rel='noopener'>Ouvrir</a>
          <button class='btn' type='button' onclick="toggleQR('qr_rep')">Afficher QR</button>
        </div>

        <div class='qr' id='qr_rep'>
          <div class='small' style='margin-bottom:8px'>Scanne avec ton téléphone</div>
          <img src='{esc(rep_qr)}' alt='QR Représentant'>
        </div>
      </div>
    </div>

    <hr>
    <a class='btn secondary' href='/contract?id={urllib.parse.quote(cid)}'>Retour au contrat</a>
    <a class='btn secondary' href='/contract/send?id={urllib.parse.quote(cid)}'>Générer de nouveaux liens</a>
  </div>
</div>

<script>
function toggleQR(id){{
  var el = document.getElementById(id);
  if(!el) return;
  el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}}
async function copyText(id){{
  var el = document.getElementById(id);
  if(!el) return;
  var text = el.innerText || el.textContent || '';
  try {{
    await navigator.clipboard.writeText(text);
    alert('Copié ✅');
  }} catch(e) {{
    // fallback
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    alert('Copié ✅');
  }}
}}
</script>
</body></html>"""
                return self.send_html(html)

            # SIGN SUBMIT (public)
            if path == "/sign/submit":
                token = (form.get("token") or "").strip()
                mode = (form.get("mode") or "draw").strip()
                png_b64 = (form.get("png_b64") or "").strip()
                sig_text = (form.get("sig_text") or "").strip()
                initials = (form.get("initials") or "").strip()
                applied = (form.get("applied") or "").strip()
                if not token:
                    return self.send_text("missing token", 400)

                tp, all_tokens, rec = token_lookup(token)
                if not rec:
                    return self.send_text("token invalid", 404)
                if rec.get("used"):
                    return self.send_text("Lien déjà utilisé.", 200)

                cid = rec["contract_id"]
                who = rec["who"]
                ensure_contract(cid)

                png_path = None
                if mode == "draw":
                    prefix = "data:image/png;base64,"
                    if not png_b64.startswith(prefix):
                        return self.send_text("bad image", 400)
                    try:
                        sig_raw = base64.b64decode(png_b64[len(prefix):])
                    except Exception:
                        return self.send_text("bad image", 400)
                    if len(sig_raw) < 80:
                        return self.send_text("empty signature", 400)
                    sig_dir = os.path.join(cdir(cid), "sig")
                    os.makedirs(sig_dir, exist_ok=True)
                    png_path = os.path.join(sig_dir, f"{who}.png")
                    with open(png_path, "wb") as f:
                        f.write(sig_raw)
                else:
                    if not sig_text:
                        return self.send_text("missing signature text", 400)

                sigs = signature_state(cid)
                sigs[who] = {
                    "who": who,
                    "saved_at": now_iso(),
                    "png_path": png_path,
                    "mode": mode,
                    "sig_text": sig_text,
                    "initials": initials,
                    "applied": [a for a in applied.split(",") if a.strip()],
                    "ip": self.client_address[0] if self.client_address else "",
                    "ua": self.headers.get("User-Agent", ""),
                    "email": rec.get("email", "")
                }
                write_json(os.path.join(cdir(cid), "signatures.json"), sigs)

                all_tokens[token]["used"] = True
                all_tokens[token]["used_at"] = now_iso()
                write_json(tp, all_tokens)

                mark_signed_if_complete(cid)
                return self.redirect(f"/sign/done?cid={urllib.parse.quote(cid)}")

            return self.send_text("Not found", 404)

        except Exception:
            self.log_exception()
            return self.send_text("Server error (see logs).", 500)

    # -------------
    # Response helpers
    # -------------
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

# -------------------------
# Entry point for Render
# -------------------------
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", "10000"))
    print(f"Starting server on {HOST}:{PORT}")
    httpd = ThreadingHTTPServer((HOST, PORT), H)
    httpd.serve_forever()
