"""
app.py — Simulador combinado para laboratorio de firmware (vulnerable + seguro)

Cómo usar:
    1. Instala Flask si no lo tienes:
       pip install flask

    2. Ejecuta:
       python app.py

    3. Visita en tu navegador:
       - Vulnerable: http://127.0.0.1:8080/vuln/
       - Seguro:    http://127.0.0.1:8080/secure/

Notas:
    - Este script está pensado para laboratorio en entorno local/aislado.
    - No exponer a Internet.
"""
from flask import Flask, request, make_response, render_template_string, redirect, url_for
import base64
import os
import hashlib
import hmac

app = Flask(__name__)
app.secret_key = os.urandom(24)

# -------------------------
# Templates (shared)
# -------------------------
BASE_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>{{ title }}</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 28px; }
      nav a { margin-right: 12px; }
      textarea { width: 100%; }
      .msg { margin: 8px 0; padding: 8px; border-radius: 4px; }
      .ok { background: #e6ffed; border: 1px solid #a6f0b3; }
      .err { background: #ffecec; border: 1px solid #f1a0a0; }
    </style>
  </head>
  <body>
    <h2>{{ title }}</h2>
    <p><b>Firmware:</b> {{ fw }}</p>
    <nav>
      <a href="{{ base }}/">Dashboard</a> |
      <a href="{{ base }}/settings">Settings</a> |
      <a href="{{ base }}/ota">OTA</a>
      {% if extra_nav %}
      | {{ extra_nav|safe }}
      {% endif %}
    </nav>
    <hr>
    <div>
      {{ body|safe }}
    </div>
  </body>
</html>
"""

# -------------------------
# Vulnerable simulator (/vuln)
# -------------------------
VULN_FW = "FW v1.0-old"
VULN_ADMIN_USER = "admin"
VULN_ADMIN_PASS = "admin"  # insecure default

def vuln_check_auth(auth_header):
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        payload = base64.b64decode(auth_header.split(" ",1)[1]).decode()
        user, pw = payload.split(":",1)
        return (user == VULN_ADMIN_USER and pw == VULN_ADMIN_PASS)
    except Exception:
        return False

def vuln_require_auth(resp_body):
    resp = make_response(resp_body, 401)
    resp.headers['WWW-Authenticate'] = 'Basic realm="Device-VULN"'
    return resp

@app.route("/vuln/")
def vuln_index():
    auth = request.headers.get("Authorization", "")
    if not vuln_check_auth(auth):
        return vuln_require_auth("Auth required (vulnerable device)")
    body = "<p>Welcome, admin. Config visible:</p><ul><li>WiFi SSID: <i>demo_wifi</i></li><li>API Key: <b>VISIBLE-PLAINTEXT</b></li></ul>"
    return render_template_string(BASE_TEMPLATE, title="Device Panel (Vulnerable)", fw=VULN_FW, body=body, base="/vuln", extra_nav=None)

@app.route("/vuln/settings", methods=["GET","POST"])
def vuln_settings():
    auth = request.headers.get("Authorization", "")
    if not vuln_check_auth(auth):
        return vuln_require_auth("Auth required (vulnerable device)")
    msg = ""
    if request.method == "POST":
        new_pw = request.form.get("new_password","")
        global VULN_ADMIN_PASS
        if len(new_pw) >= 6:
            VULN_ADMIN_PASS = new_pw  # still insecure: stored in plaintext
            msg = "<div class='msg ok'>Password changed (stored plaintext — insecure!).</div>"
        else:
            msg = "<div class='msg err'>Password too short (min 6).</div>"
    form = """
      <h3>Settings</h3>
      <form method="POST">
        <label>New admin password:</label><br>
        <input type="password" name="new_password" />
        <button type="submit">Change</button>
      </form>
    """
    return render_template_string(BASE_TEMPLATE, title="Settings (Vulnerable)", fw=VULN_FW, body=msg+form, base="/vuln", extra_nav=None)

@app.route("/vuln/ota", methods=["GET","POST"])
def vuln_ota():
    auth = request.headers.get("Authorization", "")
    if not vuln_check_auth(auth):
        return vuln_require_auth("Auth required (vulnerable device)")
    body = """
      <h3>OTA (Insecure)</h3>
      <p>This endpoint accepts any update without signature verification.</p>
      <form method="POST">
        <textarea name="blob" rows="6" placeholder="firmware blob (text)"></textarea><br>
        <button type="submit">Apply Update (insecure)</button>
      </form>
    """
    if request.method == "POST":
        body += "<div class='msg ok'>Update accepted (no signature verification) — demo only.</div>"
    return render_template_string(BASE_TEMPLATE, title="OTA (Vulnerable)", fw=VULN_FW, body=body, base="/vuln", extra_nav=None)

# -------------------------
# Secure simulator (/secure)
# -------------------------
SECURE_FW = "FW v2.1-secure"
# simple in-memory state for demo; in real device this would be NVS/secure element
SECURE_STATE = {
    "first_boot": True,
    "admin_user": "admin",
    "admin_pass_hash": None,  # store salt||dk
    "ota_shared_key": b"demo_shared_key_for_hmac"  # for HMAC demo only
}

def pbkdf2_hash(password: str, salt: bytes=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    # store salt||dk
    return salt + dk

def verify_hash(password: str, blob: bytes):
    if not blob or len(blob) < 16:
        return False
    salt = blob[:16]
    dk = blob[16:]
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return hmac.compare_digest(test, dk)

def secure_check_auth(auth_header):
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        payload = base64.b64decode(auth_header.split(" ",1)[1]).decode()
        user, pw = payload.split(":",1)
        if user != SECURE_STATE["admin_user"] or SECURE_STATE["admin_pass_hash"] is None:
            return False
        return verify_hash(pw, SECURE_STATE["admin_pass_hash"])
    except Exception:
        return False

def secure_require_auth(resp_body):
    resp = make_response(resp_body, 401)
    resp.headers['WWW-Authenticate'] = 'Basic realm="Device-SECURE"'
    return resp

@app.route("/secure/", methods=["GET","POST"])
def secure_index():
    # Force first-boot password setup
    if SECURE_STATE["first_boot"] or SECURE_STATE["admin_pass_hash"] is None:
        form = """
          <h3>First boot — Set admin password</h3>
          <form method="POST">
            <input type="password" name="pw1" placeholder="New password (12+ chars)" /><br>
            <input type="password" name="pw2" placeholder="Repeat password" /><br>
            <button type="submit">Set password</button>
          </form>
        """
        if request.method == "POST":
            p1 = request.form.get("pw1","")
            p2 = request.form.get("pw2","")
            if len(p1) >= 12 and p1 == p2:
                SECURE_STATE["admin_pass_hash"] = pbkdf2_hash(p1)
                SECURE_STATE["first_boot"] = False
                body = "<div class='msg ok'>Password set. Now use HTTP Basic Auth to access the device.</div>" + form
            else:
                body = "<div class='msg err'>Invalid password. Use 12+ chars and repeat correctly.</div>" + form
        else:
            body = form
        return render_template_string(BASE_TEMPLATE, title="Device Panel (Secure) - First Boot", fw=SECURE_FW, body=body, base="/secure", extra_nav=None)

    # Normal dashboard (requires auth)
    auth = request.headers.get("Authorization", "")
    if not secure_check_auth(auth):
        return secure_require_auth("Auth required (secure device)")
    body = "<p>Welcome. Sensitive fields are redacted. Secrets stored hashed or in secure store.</p>"
    return render_template_string(BASE_TEMPLATE, title="Device Panel (Secure)", fw=SECURE_FW, body=body, base="/secure", extra_nav=None)

@app.route("/secure/settings", methods=["GET","POST"])
def secure_settings():
    auth = request.headers.get("Authorization", "")
    if not secure_check_auth(auth):
        return secure_require_auth("Auth required (secure device)")
    msg = ""
    if request.method == "POST":
        new_pw = request.form.get("new_password","")
        if len(new_pw) >= 12:
            SECURE_STATE["admin_pass_hash"] = pbkdf2_hash(new_pw)
            msg = "<div class='msg ok'>Password changed and stored as PBKDF2 (good).</div>"
        else:
            msg = "<div class='msg err'>Password too short (min 12).</div>"
    form = """
      <h3>Settings (Hardened)</h3>
      <form method="POST">
        <label>New admin password:</label><br>
        <input type="password" name="new_password" />
        <button type="submit">Change</button>
      </form>
    """
    return render_template_string(BASE_TEMPLATE, title="Settings (Secure)", fw=SECURE_FW, body=msg+form, base="/secure", extra_nav=None)

@app.route("/secure/ota", methods=["GET","POST"])
def secure_ota():
    auth = request.headers.get("Authorization", "")
    if not secure_check_auth(auth):
        return secure_require_auth("Auth required (secure device)")
    form = """
      <h3>OTA (Signed — HMAC demo)</h3>
      <p>Upload firmware blob (text for demo) and HMAC-SHA256 signature (hex) created with the shared key.</p>
      <form method="POST">
        <textarea name="blob" rows="6" placeholder="firmware blob (text)"></textarea><br>
        <input name="sig" placeholder="hmac-sha256 hex" />
        <button type="submit">Verify & Apply</button>
      </form>
    """
    msg = ""
    if request.method == "POST":
        blob = request.form.get("blob","").encode()
        sig_hex = request.form.get("sig","").strip()
        expected = hmac.new(SECURE_STATE["ota_shared_key"], blob, hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig_hex, expected):
            msg = "<div class='msg ok'>Signature OK. Firmware applied (demo).</div>"
        else:
            msg = "<div class='msg err'>Invalid signature. Update rejected.</div>"
    return render_template_string(BASE_TEMPLATE, title="OTA (Secure)", fw=SECURE_FW, body=msg+form, base="/secure", extra_nav=None)

# Root index helps jumping to both devices
@app.route("/")
def root():
    body = """
      <p>Simulador combinado — elige una instancia:</p>
      <ul>
        <li><a href="/vuln/">Vulnerable device (admin/admin)</a></li>
        <li><a href="/secure/">Secure device (first-boot enforced)</a></li>
      </ul>
      <p><i>Nota:</i> Secure device exige establecer contraseña de 12+ chars en primer arranque.</p>
    """
    return render_template_string(BASE_TEMPLATE, title="Lab Firmware - Root", fw="(N/A)", body=body, base="/", extra_nav=None)

if __name__ == "__main__":
    # Ejecutar en 127.0.0.1:8080
    app.run(host="127.0.0.1", port=8080, debug=False)
