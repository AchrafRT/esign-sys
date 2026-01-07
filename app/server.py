#!/usr/bin/env python3
import os, json, base64, glob, secrets, urllib.parse, mimetypes, smtplib, struct, hmac, hashlib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from email.message import EmailMessage

# -------------------------
# Paths
# -------------------------
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WWW  = os.path.join(ROOT, "www")
ASSETS = os.path.join(WWW, "assets")
CFG_PX  = os.path.join(ROOT, "cfg", "field_map_px.json")
DB   = os.path.join(ROOT, "db", "contracts")
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.json")

os.makedirs(DB, exist_ok=True)

# Sessions + simple auth (stdlib only)
SESSIONS_PATH = os.path.join(ROOT, "db", "sessions.json")

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

def set_status(cid, status):
    b = load_bundle(cid)
    b.setdefault("meta", {})
    b["meta"]["contract_id"] = cid
    b["meta"].setdefault("created_at", now_iso())
    b["meta"]["status"] = status
    b["meta"]["updated_at"] = now_iso()
    save_bundle(cid, b)
    # legacy sync
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

    # legacy sync
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
    """
    Required statuses:
      - signed_client : client signed only
      - signed_rep    : rep signed only
      - signed        : both signed
    """
    s = signature_state(cid)
    has_client = bool(s.get("client"))
    has_rep = bool(s.get("rep"))

    if has_client and has_rep:
        set_status(cid, "signed")
    elif has_client:
        set_status(cid, "signed_client")
    elif has_rep:
        set_status(cid, "signed_rep")
    # else: do nothing (keep current)

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

# -------------------------
# HTTP Handler
# -------------------------
class H(BaseHTTPRequestHandler):
    # Render sometimes probes with HEAD
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "0")
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

        # Route aliases (avoid UI mismatch)
        if path == "/contracts":
            return self.redirect("/contract" + (("?" + u.query) if u.query else ""))

        # Static assets
        if path.startswith("/assets/"):
            f = os.path.join(WWW, path.lstrip("/"))
            return self.serve_file(f, None)

        # Login/logout
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

        # Public routes (must not require login)
        # IMPORTANT: include /sign/done so client/rep can finish without being bounced to login
        public_prefixes = ("/sign", "/contract/signature_image", "/contract/print")
        if not path.startswith(public_prefixes):
            if not self.require_login():
                return self.redirect_login()

        if path in ("/", "/sales"):
            tpl = read_text(os.path.join(WWW, "sales.html"))
            user = self.current_user() or ""
            return self.send_html(tpl.replace("<!--USER-->", esc(user)))

        # ---- search api
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

        # ---- SEND PAGE (THIS IS THE MISSING PIECE THAT CAUSED BLACK "NOT FOUND")
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
.card{{max-width:720px;margin:18px auto;padding:14px;border:1px solid rgba(255,255,255,.10);border-radius:16px;background:rgba(15,23,42,.60)}}
input{{width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.10);background:rgba(15,23,42,.80);color:#e5e7eb}}
label{{font-weight:900;font-size:13px}}
.hint{{font-size:12px;opacity:.8}}
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
    <button class='btn' type='submit'>Envoyer les liens</button>
  </form>
  <p class='hint'>SMTP est optionnel. Si désactivé, les liens sont enregistrés dans <code>db/contracts/{esc(cid)}/email_log.json</code>.</p>
</div>
</body></html>"""
            return self.send_html(html)

        # ---- print signed contract (public)
        if path == "/contract/print":
            cid = q.get("id", [""])[0]
            if not cid:
                return self.send_text("missing id", 400)
            ensure_contract(cid)

            cfg = read_json(CFG_PX, {"fields": [], "signature_zones": []})
            fields_map = cfg.get("fields", []) if isinstance(cfg, dict) else []
            sig_map    = cfg.get("signature_zones", []) if isinstance(cfg, dict) else []

            b = load_bundle(cid)
            fields = b.get("fields", {}) if isinstance(b.get("fields"), dict) else {}
            calc = b.get("calc", {}) if isinstance(b.get("calc"), dict) else {}
            meta = b.get("meta", {}) if isinstance(b.get("meta"), dict) else {}
            sigs = signature_state(cid)

            pages = sorted(glob.glob(os.path.join(ASSETS, "page_*.png")))
            sections = []
            for idx, p in enumerate(pages, start=1):
                img = os.path.basename(p)
                dim = png_size(p)
                if not dim:
                    continue
                iw, ih = dim
                overlay = []

                for fm in fields_map:
                    if int(fm.get("page", 0)) != idx:
                        continue
                    name = fm["name"]
                    val = deep_get(fields, name) or ""
                    cval = calc.get(name)
                    if cval is None:
                        cval = deep_get(calc, name)
                    if cval is not None and str(cval) != "":
                        val = cval

                    x = float(fm["x"]); y = float(fm["y"]); w = float(fm["w"]); h = float(fm["h"])
                    x_pct = (x / iw) * 100.0
                    y_pct = (y / ih) * 100.0
                    w_pct = (w / iw) * 100.0
                    h_pct = (h / ih) * 100.0
                    style = f"left:{x_pct:.6f}%;top:{y_pct:.6f}%;width:{w_pct:.6f}%;height:{h_pct:.6f}%;"
                    overlay.append(
                        f"<div class='field' style='{style}'>"
                        f"<div class='txt'>{esc(val)}</div>"
                        f"</div>"
                    )

                for sm in sig_map:
                    if int(sm.get("page", 0)) != idx:
                        continue
                    who = sm.get("who")
                    x = float(sm["x"]); y = float(sm["y"]); w = float(sm["w"]); h = float(sm["h"])
                    x_pct = (x / iw) * 100.0
                    y_pct = (y / ih) * 100.0
                    w_pct = (w / iw) * 100.0
                    h_pct = (h / ih) * 100.0
                    style = f"left:{x_pct:.6f}%;top:{y_pct:.6f}%;width:{w_pct:.6f}%;height:{h_pct:.6f}%;"
                    rec = sigs.get(who) or {}
                    if rec:
                        if rec.get("mode") == "text":
                            t = esc(rec.get("sig_text") or "")
                            ini = esc(rec.get("initials") or "")
                            overlay.append(
                                f"<div class='sigzone' style='{style};border:none'>"
                                f"<div style='width:100%;height:100%;display:flex;flex-direction:column;justify-content:center;align-items:flex-start;padding:6px 8px;background:rgba(255,255,255,.0)'>"
                                f"<div style='font-family:cursive;font-size:22px;line-height:1'>{t}</div>"
                                f"<div style='font-size:12px;font-weight:900;opacity:.75'>{ini}</div>"
                                f"</div></div>"
                            )
                        else:
                            v = urllib.parse.quote(str(rec.get("saved_at","")))
                            overlay.append(
                                f"<div class='sigzone' style='{style};border:none'>"
                                f"<img src='/contract/signature_image?id={urllib.parse.quote(cid)}&who={urllib.parse.quote(who)}&v={v}' alt='Signature'>"
                                f"</div>"
                            )

                sections.append(
                    f"<section class='page'>"
                    f"<img class='bg' src='/assets/{esc(img)}' alt='Page {idx}'>"
                    f"<div class='overlay'>{''.join(overlay)}</div>"
                    f"</section>"
                )

            title = f"Contrat signé — {cid}"
            html = f"""<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{esc(title)}</title>
<style>
:root{{--page-w:210mm;--page-h:297mm;--ink:#0b0f19;--line:#e6e8ee;--bg:#fff}}
*{{box-sizing:border-box}}body{{margin:0;font-family:system-ui;background:var(--bg);color:var(--ink)}}
.topbar{{position:sticky;top:0;z-index:50;display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 14px;background:rgba(255,255,255,.95);border-bottom:1px solid var(--line)}}
.btn{{appearance:none;border:1px solid var(--line);background:#0b0f19;color:#fff;padding:8px 12px;border-radius:12px;cursor:pointer;text-decoration:none;font-weight:900}}
.btn.secondary{{background:#fff;color:#0b0f19}}
.wrap{{max-width:calc(var(--page-w) + 120px);margin:16px auto 80px;padding:0 14px}}
.page{{width:var(--page-w);height:var(--page-h);margin:18px auto;background:#fff;border:1px solid var(--line);border-radius:18px;position:relative;overflow:hidden}}
.page img.bg{{width:100%;height:100%;display:block;object-fit:cover}}
.overlay{{position:absolute;inset:0}}.field{{position:absolute}}
.field .txt{{width:100%;height:100%;display:flex;align-items:center;justify-content:flex-start;padding:2px 4px;font-size:12px;white-space:nowrap;overflow:hidden}}
.sigzone{{position:absolute;border:0;overflow:hidden}}
.sigzone img{{width:100%;height:100%;object-fit:contain}}
@media print{{.topbar{{display:none}}.wrap{{max-width:none;margin:0;padding:0}}.page{{border:none;margin:0;border-radius:0;page-break-after:always}}}}
</style></head><body>
<div class='topbar'>
  <div style='font-weight:1000'>Contrat signé — {esc(cid)}</div>
  <a class='btn secondary' href='#' onclick='window.print();return false;'>Imprimer / Enregistrer PDF</a>
</div>
<div class='wrap'>
  <div style='font-size:12px;opacity:.8;margin:10px 0'>Statut: <b>{esc(meta.get('status',''))}</b></div>
  {''.join(sections)}
</div>
</body></html>"""
            return self.send_html(html)

        # ---- mapper tool
        if path == "/mapper":
            pageno = int(q.get("page", ["1"])[0] or "1")
            pages = sorted(glob.glob(os.path.join(ASSETS, "page_*.png")))
            if pageno < 1 or pageno > len(pages):
                return self.send_text("bad page", 400)
            img = os.path.basename(pages[pageno-1])
            tpl = read_text(os.path.join(WWW, "mapper.html"))
            html = tpl.replace("<!--PAGENO-->", str(pageno)).replace("<!--IMGURL-->", f"/assets/{esc(img)}")
            return self.send_html(html)

        # ---- contract view
        if path in ("/contract",):
            cid = q.get("id", [None])[0] or ("c_" + secrets.token_hex(8))
            ensure_contract(cid)

            cfg = read_json(CFG_PX, {"fields": [], "signature_zones": []})
            fields_map = cfg.get("fields", []) if isinstance(cfg, dict) else []
            sig_map    = cfg.get("signature_zones", []) if isinstance(cfg, dict) else []

            b = load_bundle(cid)
            fields = b.get("fields", {})
            fields = fields if isinstance(fields, dict) else {}
            calc = b.get("calc", {})
            calc = calc if isinstance(calc, dict) else {}
            status = (b.get("meta", {}) or {}).get("status", "empty")

            sigs = signature_state(cid)

            pages = sorted(glob.glob(os.path.join(ASSETS, "page_*.png")))
            sections = []
            for idx, p in enumerate(pages, start=1):
                img = os.path.basename(p)
                dim = png_size(p)
                if not dim:
                    continue
                iw, ih = dim
                overlay = []

                for fm in fields_map:
                    if int(fm.get("page", 0)) != idx:
                        continue
                    name = fm["name"]
                    kind = fm.get("kind", "text")
                    readonly = bool(fm.get("readonly", False))

                    val = deep_get(fields, name) or ""
                    cval = calc.get(name)
                    if cval is None:
                        cval = deep_get(calc, name)
                    if cval is not None and str(cval) != "":
                        val = cval
                        readonly = True

                    x = float(fm["x"]); y = float(fm["y"]); w = float(fm["w"]); h = float(fm["h"])
                    x_pct = (x / iw) * 100.0
                    y_pct = (y / ih) * 100.0
                    w_pct = (w / iw) * 100.0
                    h_pct = (h / ih) * 100.0
                    style = f"left:{x_pct:.6f}%;top:{y_pct:.6f}%;width:{w_pct:.6f}%;height:{h_pct:.6f}%;"

                    itype = "text"
                    checked = ""
                    if kind == "email":
                        itype = "email"
                    elif kind == "date":
                        itype = "date"
                    elif kind == "checkbox":
                        itype = "checkbox"
                        v = str(val).strip().lower()
                        if v in ("1","true","on","yes","x","checked"):
                            checked = " checked"
                        val = "1"

                    ro = " readonly" if readonly else ""
                    overlay.append(
                        f"<div class='field' style='{style}'>"
                        f"<input name='{esc(name)}' type='{itype}' value='{esc(val)}'{checked}{ro}>"
                        f"</div>"
                    )

                for sm in sig_map:
                    if int(sm.get("page", 0)) != idx:
                        continue
                    who = sm.get("who")
                    label = sm.get("label", "Signature")
                    x = float(sm["x"]); y = float(sm["y"]); w = float(sm["w"]); h = float(sm["h"])
                    x_pct = (x / iw) * 100.0
                    y_pct = (y / ih) * 100.0
                    w_pct = (w / iw) * 100.0
                    h_pct = (h / ih) * 100.0
                    style = f"left:{x_pct:.6f}%;top:{y_pct:.6f}%;width:{w_pct:.6f}%;height:{h_pct:.6f}%;"

                    signed = bool(sigs.get(who))
                    if signed:
                        rec = sigs.get(who) or {}
                        if rec.get("mode") == "text":
                            t = esc(rec.get("sig_text") or "")
                            ini = esc(rec.get("initials") or "")
                            overlay.append(
                                f"<div class='sigzone' style='{style};border-style:solid'>"
                                f"<div style='width:100%;height:100%;display:flex;flex-direction:column;justify-content:center;align-items:flex-start;padding:8px 10px;background:rgba(255,255,255,.55)'>"
                                f"<div style='font-family:cursive;font-size:22px;line-height:1'>{t}</div>"
                                f"<div style='font-size:12px;font-weight:900;opacity:.8'>{ini}</div>"
                                f"</div></div>"
                            )
                        else:
                            v = urllib.parse.quote(str(rec.get("saved_at","")))
                            overlay.append(
                                f"<div class='sigzone' style='{style}'>"
                                f"<img src='/contract/signature_image?id={urllib.parse.quote(cid)}&who={urllib.parse.quote(who)}&v={v}' alt='Signature'>"
                                f"</div>"
                            )
                    else:
                        overlay.append(
                            f"<div class='sigzone' style='{style}'>"
                            f"<div class='lock'>"
                            f"<div>{esc(label)}</div>"
                            f"<div class='small'>Zone verrouillée — envoyer pour signature</div>"
                            f"<a class='btn secondary' href='/contract/send?id={urllib.parse.quote(cid)}'>Envoyer</a>"
                            f"</div></div>"
                        )

                sections.append(
                    f"<section class='page'>"
                    f"<img class='bg' src='/assets/{esc(img)}' alt='Page {idx}'>"
                    f"<div class='overlay'>{''.join(overlay)}</div>"
                    f"</section>"
                )

            topbar = (
                f"<div class='topbar'>"
                f"<div class='brand'>9999 — Contrat</div>"
                f"<div class='pill'>Statut: <b id='status'>{esc(status)}</b></div>"
                f"<input type='hidden' name='contract_id' value='{esc(cid)}'>"
                f"<button class='btn' type='submit'>Sauvegarder &amp; Calculer</button>"
                f"<a class='btn secondary' href='/contract/send?id={urllib.parse.quote(cid)}'>Envoyer</a>"
                f"<a class='btn secondary' href='#' onclick='window.print();return false;'>Imprimer</a>"
                f"<a class='btn secondary' href='/assets/contract_template.pdf' download>PDF original</a>"
                f"<span class='hint'>Mapper: /mapper?page=1</span>"
                f"</div>"
            )

            tpl = read_text(os.path.join(WWW, "contract.html"))
            html = tpl.replace("<!--TOPBAR-->", topbar).replace("<!--PAGES-->", "".join(sections))
            return self.send_html(html)

        # ---- signature image (public)
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

        # ---- sign flow (public)
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
    <p style='margin:0 0 10px 0'>Vous pouvez maintenant télécharger une version PDF (via impression) du contrat signé.</p>
    <a class='btn' href='/contract/print?id={urllib.parse.quote(cid)}' target='_blank'>Télécharger PDF (imprimer)</a>
    <a class='btn secondary' href='/contract?id={urllib.parse.quote(cid)}' target='_blank'>Voir le contrat</a>
  </div>
</div>
</body></html>"""
            return self.send_html(html)

        return self.send_text("Not found", 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path

        # POST alias for UI mismatch
        if path == "/contracts/save":    path = "/contract/save"
        if path == "/contracts/compute": path = "/contract/compute"
        if path == "/contracts/send":    path = "/contract/send"

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

        # SAVE
        if path == "/contract/save":
            cid = (form.get("contract_id") or "").strip()
            if not cid:
                return self.send_text("missing contract_id", 400)
            ensure_contract(cid)

            b = load_bundle(cid)
            fields = b.get("fields", {})
            fields = fields if isinstance(fields, dict) else {}

            for k, v in form.items():
                if k == "contract_id":
                    continue
                deep_set(fields, k, v)

            fields["_meta"] = {"updated_at": now_iso()}
            b["fields"] = fields

            calc_and_store(cid, fields)
            set_status(cid, "draft")
            return self.redirect(f"/contract?id={urllib.parse.quote(cid)}")

        # COMPUTE
        if path == "/contract/compute":
            cid = (form.get("contract_id") or "").strip() or None

            fields = {}
            for k, v in form.items():
                if k == "contract_id":
                    continue
                deep_set(fields, k, v)

            if cid:
                b = load_bundle(cid)
                saved = b.get("fields", {})
                if isinstance(saved, dict):
                    merged = saved

                    def merge_in(dst, src):
                        for kk, vv in src.items():
                            if isinstance(vv, dict) and isinstance(dst.get(kk), dict):
                                merge_in(dst[kk], vv)
                            else:
                                dst[kk] = vv

                    merge_in(merged, fields)
                    fields = merged

            calc = compute_calculations(fields)

            calc["pricing.subtotal"] = calc.get("Prix_de_vente_avant_taxes", "")
            calc["pricing.tps"] = calc.get("TPS_5_730072220RT0001", "")
            calc["pricing.tvq"] = calc.get("TVQ_9975_1232208119TQ0001", "")
            calc["pricing.total_with_tax"] = calc.get("Total_prix_de_vente_avec_taxes", "")

            try:
                total_with_tax_num = float(calc.get("Total_prix_de_vente_avec_taxes", "0") or 0)
            except Exception:
                total_with_tax_num = 0.0

            calc["payments.no_finance.amount_at_measure"] = money(total_with_tax_num * 0.40)
            calc["payments.no_finance.amount_pre_delivery"] = money(total_with_tax_num * 0.60)
            calc["undefined"] = calc["payments.no_finance.amount_at_measure"]
            calc["undefined_2"] = calc["payments.no_finance.amount_pre_delivery"]

            if cid:
                b = load_bundle(cid)
                b["fields"] = fields if isinstance(fields, dict) else {}
                b["calc"] = calc if isinstance(calc, dict) else {}
                save_bundle(cid, b)
                write_json(os.path.join(cdir(cid), "fields.json"), b["fields"])
                write_json(os.path.join(cdir(cid), "calc.json"), b["calc"])

            payload = json.dumps({"ok": True, "calc": calc}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # SEND (creates 2 tokens, logs links, updates status)
        if path == "/contract/send":
            cid = (form.get("contract_id") or "").strip()
            client_email = (form.get("client_email") or "").strip()
            rep_email = (form.get("rep_email") or "").strip()
            if not cid or not client_email or not rep_email:
                return self.send_text("missing", 400)
            ensure_contract(cid)

            # creating tokens implies "to_sign"
            set_status(cid, "to_sign")

            t_client = store_token(cid, "client", client_email)
            t_rep = store_token(cid, "rep", rep_email)

            settings = read_json(SETTINGS_PATH, {})
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
                "client_email": client_email, "rep_email": rep_email,
                "client_link": link_client, "rep_link": link_rep,
                "smtp_client": {"ok": ok1, "msg": msg1},
                "smtp_rep": {"ok": ok2, "msg": msg2},
            })

            return self.redirect(f"/contract?id={urllib.parse.quote(cid)}")

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

            # updates status to signed_client / signed_rep / signed
            mark_signed_if_complete(cid)

            return self.redirect(f"/sign/done?cid={urllib.parse.quote(cid)}")

        return self.send_text("Not found", 404)

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
