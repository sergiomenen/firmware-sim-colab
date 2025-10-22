
"""
app.py — Laboratorio de Firmware (Vulnerable vs Seguro) en un solo archivo
Alineado con la actividad "Firmware vulnerable y contraseñas por defecto".
Uso local / GitHub (run local): `pip install flask` y `python app.py`

Rutas principales:
  - Vulnerable: http://127.0.0.1:8080/vuln/
  - Seguro:     http://127.0.0.1:8080/secure/

Qué demuestra:
  (1) Login con credenciales por defecto (admin/admin) y exposición de datos sensibles.
  (2) Remediación: primer arranque, hash de contraseña (PBKDF2) y OTA con verificación (HMAC demo).
  (3) Verificación final: el login por defecto ya no funciona.

⚠️ Ética: Úsalo solo en laboratorio/local. No expongas este servidor a Internet.
"""
from flask import Flask, request, make_response, render_template_string
import os, base64, hashlib, hmac

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ================================
# Template HTML compartido
# ================================
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
      input[type=text], input[type=password] { width: 320px; }
      .msg { margin: 10px 0; padding: 10px; border-radius: 6px; }
      .ok { background: #e6ffed; border: 1px solid #a6f0b3; }
      .err { background: #ffecec; border: 1px solid #f1a0a0; }
      code { background: #f7f7f7; padding: 2px 4px; border-radius: 4px; }
      .tip { color: #555; }
      .card { border:1px solid #eee; padding: 12px; border-radius: 8px; }
    </style>
  </head>
  <body>
    <h2>{{ title }}</h2>
    <p><b>Firmware:</b> {{ fw }}</p>
    <nav>
      <a href="{{ base }}/">Dashboard</a> |
      <a href="{{ base }}/settings">Settings</a> |
      <a href="{{ base }}/ota">OTA</a>
      {% if extra_nav %}| {{ extra_nav|safe }}{% endif %}
    </nav>
    <hr>
    <div>
      {{ body|safe }}
    </div>
  </body>
</html>
"""

# ================================
# Sección Vulnerable (/vuln/*)
# ================================
VULN_FW = "FW v1.0-old"
VULN_ADMIN_USER = "admin"
VULN_ADMIN_PASS = "admin"  # INSEGURO: credenciales por defecto

def _vuln_check_auth(auth_header: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        payload = base64.b64decode(auth_header.split(" ",1)[1]).decode()
        user, pw = payload.split(":",1)
        return (user == VULN_ADMIN_USER and pw == VULN_ADMIN_PASS)
    except Exception:
        return False

def _vuln_require_auth(msg="Auth required (vulnerable device)"):
    resp = make_response(msg, 401)
    resp.headers['WWW-Authenticate'] = 'Basic realm="Device-VULN"'
    return resp

@app.route("/vuln/")
def vuln_index():
    auth = request.headers.get("Authorization", "")
    if not _vuln_check_auth(auth):
        return _vuln_require_auth()
    body = """
    <div class='card'>
      <p><b>Bienvenido, admin.</b> Datos sensibles (demostración):</p>
      <ul>
        <li>WiFi SSID: <i>demo_wifi</i></li>
        <li>API Key: <b>VISIBLE-PLAINTEXT</b></li>
        <li class='tip'>⚠️ Malas prácticas: secretos en texto claro y credenciales por defecto.</li>
      </ul>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Device Panel (Vulnerable)",
                                  fw=VULN_FW, body=body, base="/vuln", extra_nav=None)

@app.route("/vuln/settings", methods=["GET","POST"])
def vuln_settings():
    auth = request.headers.get("Authorization", "")
    if not _vuln_check_auth(auth):
        return _vuln_require_auth()
    msg = ""
    if request.method == "POST":
        new_pw = request.form.get("new_password","")
        global VULN_ADMIN_PASS
        if len(new_pw) >= 6:
            VULN_ADMIN_PASS = new_pw  # Sigue inseguro: sin hash
            msg = "<div class='msg ok'>Password cambiada (almacenada en claro — INSEGURO).</div>"
        else:
            msg = "<div class='msg err'>Password demasiado corta (mín. 6).</div>"
    form = """
    <h3>Settings</h3>
    <form method="POST">
      <label>New admin password:</label><br>
      <input type="password" name="new_password" />
      <button type="submit">Change</button>
    </form>
    """
    return render_template_string(BASE_TEMPLATE, title="Settings (Vulnerable)",
                                  fw=VULN_FW, body=msg+form, base="/vuln", extra_nav=None)

@app.route("/vuln/ota", methods=["GET","POST"])
def vuln_ota():
    auth = request.headers.get("Authorization", "")
    if not _vuln_check_auth(auth):
        return _vuln_require_auth()
    body = """
    <h3>OTA (Insecure)</h3>
    <p>Este endpoint acepta actualizaciones <b>sin verificación</b> de firma.</p>
    <form method="POST">
      <textarea name="blob" rows="6" placeholder="firmware blob (texto)"></textarea><br>
      <button type="submit">Apply Update (insecure)</button>
    </form>
    """
    if request.method == "POST":
        body += "<div class='msg ok'>Update aceptada (sin firma) — solo demo.</div>"
    return render_template_string(BASE_TEMPLATE, title="OTA (Vulnerable)",
                                  fw=VULN_FW, body=body, base="/vuln", extra_nav=None)

# ================================
# Sección Segura (/secure/*)
# ================================
SECURE_FW = "FW v2.1-secure"
STATE = {
    "first_boot": True,
    "admin_user": "admin",
    "admin_pass_hash": None,              # almacenamos salt||dk
    "ota_shared_key": b"demo_shared_key_for_hmac"  # DEMO HMAC (sólo laboratorio)
}

def _pbkdf2_hash(password: str, salt: bytes=None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt + dk

def _verify_hash(password: str, blob: bytes) -> bool:
    if not blob or len(blob) < 16:
        return False
    salt, dk = blob[:16], blob[16:]
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return hmac.compare_digest(test, dk)

def _secure_check_auth(auth_header: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        payload = base64.b64decode(auth_header.split(" ",1)[1]).decode()
        user, pw = payload.split(":",1)
        if user != STATE["admin_user"] or STATE["admin_pass_hash"] is None:
            return False
        return _verify_hash(pw, STATE["admin_pass_hash"])
    except Exception:
        return False

def _secure_require_auth(msg="Auth required (secure device)"):
    resp = make_response(msg, 401)
    resp.headers['WWW-Authenticate'] = 'Basic realm="Device-SECURE"'
    return resp

@app.route("/secure/", methods=["GET","POST"])
def secure_index():
    # Primer arranque — obliga a establecer contraseña robusta
    if STATE["first_boot"] or STATE["admin_pass_hash"] is None:
        form = """
        <h3>First boot — Set admin password</h3>
        <form method="POST">
          <input type="password" name="pw1" placeholder="New password (12+ chars)" /><br>
          <input type="password" name="pw2" placeholder="Repeat password" /><br>
          <button type="submit">Set password</button>
        </form>
        <p class="tip">Consejo: usa al menos 12 caracteres y combina tipos.</p>
        """
        if request.method == "POST":
            p1, p2 = request.form.get("pw1",""), request.form.get("pw2","")
            if len(p1) >= 12 and p1 == p2:
                STATE["admin_pass_hash"] = _pbkdf2_hash(p1)
                STATE["first_boot"] = False
                body = "<div class='msg ok'>Password establecida. Usa HTTP Basic Auth para entrar.</div>" + form
            else:
                body = "<div class='msg err'>Password inválida. Revisa longitud y coincidencia.</div>" + form
        else:
            body = form
        return render_template_string(BASE_TEMPLATE, title="Device Panel (Secure) - First Boot",
                                      fw=SECURE_FW, body=body, base="/secure", extra_nav="<a href='/'>Home</a>")

    # Dashboard normal (requiere autenticación)
    auth = request.headers.get("Authorization", "")
    if not _secure_check_auth(auth):
        return _secure_require_auth()
    body = """
    <div class='card'>
      <p>Bienvenido. Los campos sensibles están <b>protegidos</b> (hash/secure store).
         Este panel ilustra buenas prácticas: sin secretos en claro y sin credenciales por defecto.</p>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Device Panel (Secure)",
                                  fw=SECURE_FW, body=body, base="/secure", extra_nav="<a href='/secure/sign'>HMAC Helper</a>")

@app.route("/secure/settings", methods=["GET","POST"])
def secure_settings():
    auth = request.headers.get("Authorization", "")
    if not _secure_check_auth(auth):
        return _secure_require_auth()
    msg = ""
    if request.method == "POST":
        new_pw = request.form.get("new_password","")
        if len(new_pw) >= 12:
            STATE["admin_pass_hash"] = _pbkdf2_hash(new_pw)
            msg = "<div class='msg ok'>Password actualizada (PBKDF2 almacenado con sal).</div>"
        else:
            msg = "<div class='msg err'>Password demasiado corta (mín. 12).</div>"
    form = """
    <h3>Settings (Hardened)</h3>
    <form method="POST">
      <label>New admin password:</label><br>
      <input type="password" name="new_password" />
      <button type="submit">Change</button>
    </form>
    """
    return render_template_string(BASE_TEMPLATE, title="Settings (Secure)",
                                  fw=SECURE_FW, body=msg+form, base="/secure", extra_nav="<a href='/secure/sign'>HMAC Helper</a>")

@app.route("/secure/ota", methods=["GET","POST"])
def secure_ota():
    auth = request.headers.get("Authorization", "")
    if not _secure_check_auth(auth):
        return _secure_require_auth()
    form = """
    <h3>OTA (Signed — HMAC demo)</h3>
    <p>Sube el blob de "firmware" (texto demo) y la firma HMAC-SHA256 (hex) generada con la clave compartida de laboratorio.</p>
    <form method="POST">
      <textarea name="blob" rows="6" placeholder="firmware blob (text)"></textarea><br>
      <input name="sig" placeholder="hmac-sha256 hex" />
      <button type="submit">Verify & Apply</button>
    </form>
    <p class="tip">Para facilitar la práctica, usa la herramienta <a href="/secure/sign">HMAC Helper</a> para generar la firma localmente.</p>
    """
    msg = ""
    if request.method == "POST":
        blob = request.form.get("blob","").encode()
        sig_hex = request.form.get("sig","").strip()
        expected = hmac.new(STATE["ota_shared_key"], blob, hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig_hex, expected):
            msg = "<div class='msg ok'>Firma válida. Firmware aplicado (demo).</div>"
        else:
            msg = "<div class='msg err'>Firma inválida. Update rechazado.</div>"
    return render_template_string(BASE_TEMPLATE, title="OTA (Secure)",
                                  fw=SECURE_FW, body=msg+form, base="/secure", extra_nav="<a href='/secure/sign'>HMAC Helper</a>")

# Utilidad: generador de firma HMAC para la demo (no usar en producción)
@app.route("/secure/sign", methods=["GET","POST"])
def secure_sign_helper():
    form = """
    <h3>HMAC Helper (solo demo)</h3>
    <p>Introduce el mismo blob que subirás en OTA para obtener la firma HMAC-SHA256 (hex).</p>
    <form method="POST">
      <textarea name="blob" rows="6" placeholder="firmware blob (text)"></textarea><br>
      <button type="submit">Sign locally</button>
    </form>
    """
    msg = ""
    if request.method == "POST":
        blob = request.form.get("blob","").encode()
        sig_hex = hmac.new(STATE["ota_shared_key"], blob, hashlib.sha256).hexdigest()
        msg = f"<div class='msg ok'>Signature (hex): <code>{sig_hex}</code></div>"
    return render_template_string(BASE_TEMPLATE, title="HMAC Helper",
                                  fw=SECURE_FW, body=msg+form, base="/secure", extra_nav="<a href='/secure/ota'>Volver a OTA</a>")

# ================================
# Índice raíz
# ================================
@app.route("/")
def root():
    body = """
    <p>Elige una instancia para seguir la práctica (tomar capturas y cumplir entregables):</p>
    <ul>
      <li><a href="/vuln/">Vulnerable device (admin/admin)</a></li>
      <li><a href="/secure/">Secure device (primer arranque + PBKDF2 + OTA firmada)</a></li>
    </ul>
    <div class='tip'>
      <p><b>Checklist de capturas:</b></p>
      <ol>
        <li>Interfaz inicial y versión de firmware.</li>
        <li>Acceso con credenciales por defecto (solo en <i>vuln</i>).</li>
        <li>Confirmación de cambio de contraseña.</li>
        <li>Verificación final (rechazo de <code>admin/admin</code> en el modo seguro).</li>
      </ol>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Lab Firmware — Inicio",
                                  fw="(N/A)", body=body, base="/", extra_nav=None)

if __name__ == "__main__":
    # Ejecutar en 127.0.0.1:8080
    app.run(host="127.0.0.1", port=8080, debug=False)    
