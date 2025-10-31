# webserver.py

from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, g, session
import os
import sys
import json
import traceback
from waitress import serve
import socket
import subprocess  # ✅ Add this at the top with other imports
from werkzeug.utils import secure_filename
from functools import wraps  # ✅ for auth decorator
import secrets   # ✅ for per-request realm nonce

# ================= AUTH =================
# We try to load password from /etc/rssi-gatewayapi/config.json first.
# Fallback order:
#   1. config.json["password"] (device config)
#   2. $SERVER_PASSWORD env var
#   3. hardcoded default "bleedio-x52"
# Password source: config.json (later we’ll swap in config.json logic, but keeping env/default for now)
SERVER_PASSWORD = os.getenv("SERVER_PASSWORD", "bleedio-x52")
AUTH_REALM = "BleedIO AP"
global LOGGED_OUT  
LOGGED_OUT = False
CHECK_AUTH = False

# This nonce is our "session generation". If it changes, all previous auth headers become invalid.
AUTH_NONCE = secrets.token_hex(8)

def _auth_challenge():
    """
    Instead of HTTP Basic 401 + WWW-Authenticate (popup),
    send the user to our /login form and remember where they were going.
    """
    next_url = request.path or "/"
    # mark not-authenticated
    g.is_authenticated = False
    # no browser popup anymore, just redirect
    return redirect(url_for("login", next=next_url))

def _logout_page():
    """
    Return a normal 200 OK page that:
    - Immediately refreshes to "/"
    - Attempts to 'poison' cached basic auth creds by loading a resource
      with fake credentials in the URL (works in most desktop browsers).

    We intentionally do NOT return 401 here because that would trigger
    the browser login popup you complained about.
    """
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <meta http-equiv="refresh" content="0; url=/" />
        <title>Logged out</title>
        <style>
          body { font-family: Arial, sans-serif; background:#f4f6f8; padding:40px; color:#333; }
          .box {
            max-width:400px; margin:40px auto; background:#fff; border-radius:12px;
            box-shadow:0 4px 12px rgba(0,0,0,0.08); padding:24px 28px;
            text-align:center; line-height:1.4;
          }
          .small { font-size:13px; color:#666; margin-top:12px; }
          img { display:none; }
        </style>
      </head>
      <body>
        <div class="box">
          <div>Signing you out…</div>
          <div class="small">Redirecting to status page</div>
        </div>

        <!--
          Auth poison attempts (best-effort):
          We try to "log in" with bogus creds to protected routes so
          the browser forgets the good creds it cached.
          We hide them with display:none.
        -->
        <img src="//logout:logout@127.0.0.1/wifi" alt="" />
        <img src="//logout:logout@localhost/wifi" alt="" />
      </body>
    </html>
    """

    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp

def require_auth(view_fn):
    """
    New auth wrapper:
    - trust Flask session cookie instead of HTTP Basic.
    - if not logged in, bounce to /login (no browser popup).
    """
    @wraps(view_fn)
    def wrapper(*args, **kwargs):
        logged_in = session.get("logged_in", False)

        print(
            "[require_auth] logged_in:",
            logged_in,
            "SERVER_PASSWORD set:",
            bool(SERVER_PASSWORD),
        )

        if logged_in:
            # mark for templates
            g.is_authenticated = True

            inner_resp = view_fn(*args, **kwargs)
            resp = make_response(inner_resp) if not isinstance(inner_resp, tuple) else make_response(*inner_resp)
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            return resp

        # not logged in -> redirect to /login
        g.is_authenticated = False
        return _auth_challenge()

    return wrapper
# ================= END AUTH =================

LOG_FILE = "/tmp/wifi-fallback-web.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")
    print(msg)

log("🔧 Starting Wi-Fi Config Web Server...")

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)  # needed for Flask session cookies
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB cap
ALLOWED_EXTENSIONS = {'deb'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_port_in_use(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def get_configured_networks():
    # Saved Wi‑Fi profiles (TYPE is '802-11-wireless', not 'wifi')
    lines = subprocess.run(
        "nmcli -t -f NAME,TYPE connection show",
        shell=True, capture_output=True, text=True, check=False
    ).stdout.splitlines()

    saved = []
    for l in lines:
        parts = l.split(":", 1)
        if len(parts) == 2 and parts[1] == "802-11-wireless":
            name = parts[0]
            if name != "Hotspot":  # hide the AP profile from the “saved” list
                saved.append(name)

    # Active connections (NAME + DEVICE)
    active_lines = subprocess.run(
        "nmcli -t -f NAME,DEVICE connection show --active",
        shell=True, capture_output=True, text=True, check=False
    ).stdout.splitlines()

    active = {}
    for l in active_lines:
        parts = l.split(":")
        if len(parts) >= 2:
            active[parts[0]] = parts[1]  # NAME -> DEVICE

    # Build data for template
    return [{"name": n, "active": n in active, "device": active.get(n)} for n in saved]

@app.context_processor
def inject_hostname():
    open_mode = (SERVER_PASSWORD.strip() == "" or SERVER_PASSWORD.strip().lower() in ["none", "open"])
    is_auth = getattr(g, "is_authenticated", False)
    print(f"g.is_authenticated = {is_auth}")
    return {
        "hostname": socket.gethostname(),
        "auth_banner": is_auth,
        "auth_open": open_mode,
    }

@app.route('/')
def status():
    log("✅ index page displayed.")
    try:
        # public route → explicitly mark unauthenticated
        g.is_authenticated = False
        result = subprocess.run(
            ["systemctl", "status", "rssi-gatewayapi"],
            capture_output=True, text=True
        )

        # Read config.json if exists
        config_path = "/etc/rssi-gatewayapi/config.json"
        config_data = {}
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    config_data = json.load(f)
            except Exception as e:
                config_data = {"error": f"Failed to read config.json: {e}"}

        return render_template(
            'status.html',
            status=result.stdout,
            config=config_data
        )
    except Exception:
        log("❌ Exception in `/` route:\n" + traceback.format_exc())
        return "Internal Server Error", 500
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Simple username/password form login.
    Username is fixed to 'admin', password is SERVER_PASSWORD.
    On success we set session['logged_in']=True and redirect.
    """
    # already logged in? go to next / wifi
    if session.get("logged_in"):
        return redirect(request.args.get("next") or url_for("wifi"))

    if request.method == 'POST':
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        good = (
            username == "admin" and
            password == SERVER_PASSWORD
        )

        print(
            "[/login] attempt:",
            {"username": username, "password_len": len(password)},
            "good:", good
        )

        if good:
            session["logged_in"] = True
            g.is_authenticated = True
            # reset old flags so templates don't show "logged out" banner
            global LOGGED_OUT, CHECK_AUTH
            LOGGED_OUT = False
            CHECK_AUTH = False
            return redirect(request.args.get("next") or url_for("wifi"))

        # bad creds → show form again with error
        # (we rely on login.html template to show {{ error }})
        g.is_authenticated = False
        return render_template('login.html', error="Invalid credentials")

    # GET: show login form
    g.is_authenticated = False
    return render_template('login.html', error=None)

@app.route('/logout', methods=['GET'])
def logout():
    log("👋 Logout requested via /logout")
    # clear cookie session and mark not-auth
    session.clear()
    g.is_authenticated = False
    return redirect(url_for('status'))

@app.route('/logout_basic', methods=['GET'])
def logout_basic():
    log("👋 Logout requested via /logout")
    global LOGGED_OUT, CHECK_AUTH
    LOGGED_OUT = True  # lock down protected routes until fresh auth
    # treat logout page itself as unauthenticated
    CHECK_AUTH = True  #force check
    g.is_authenticated = False
    return _logout_page()

@app.route('/wifi', methods=['GET', 'POST'])
@require_auth
def wifi():
    log("✅ wifi page displayed.")
    try:
        if request.method == 'POST':
            ssid = request.form['ssid'].strip()
            password = request.form['password'].strip()
            log(f"📥 Received credentials: SSID='{ssid}'")

            # Delete old profile if exists
            os.system(f"mount -o remount,rw / ")  # in case root is read-only
            os.system(f"systemctl restart NetworkManager")  # in case root is read-only
            os.system(f"nmcli connection delete '{ssid}' 2>/dev/null")

            # Add a new Wi-Fi connection
            os.system(f"nmcli connection add type wifi ifname wlan0 con-name '{ssid}' ssid '{ssid}'")
            os.system(f"nmcli connection modify '{ssid}' 802-11-wireless.mode infrastructure wifi-sec.key-mgmt wpa-psk")
            os.system(f"nmcli connection modify '{ssid}' wifi-sec.psk '{password}' connection.autoconnect yes")

            # Switch from Hotspot to this network
            os.system("nmcli connection down bleedio-ap 2>/dev/null")
            os.system("nmcli radio wifi on")
            os.system(f"nmcli connection up '{ssid}' 2>/dev/null")

            log("✅ Wi-Fi connection created via nmcli and activation attempted")
            return redirect(url_for('confirmation'))

        networks = get_configured_networks()
        return render_template('wifi.html', networks=networks)
    except Exception:
        log("❌ Exception in `/wifi` route:\n" + traceback.format_exc())
        return "Internal Server Error", 500

@app.route('/confirmation')
@require_auth
def confirmation():
    log("✅ Confirmation page displayed.")
    return render_template('confirmation.html')

@app.route('/cancel', methods=['POST'])
@require_auth
def cancel():
    log("❌ Shut down AP...")
    os.system("nmcli connection down Hotspot")
    print("Hotspot stopped. You can now close this page.")  # to server stdout/log
    #return redirect(url_for('confirmation'))

@app.route('/reboot', methods=['GET'])
@require_auth
def reboot_get():
    return "Method Not Allowed", 405

@app.route('/reboot', methods=['POST'])
@require_auth
def reboot():
    log("🔁 Reboot triggered from web")
    os.system("reboot")
    print("Rebooting...")
    return "Rebooting…", 200

@app.route('/upload', methods=['GET'])
@require_auth
def upload_form():
    return render_template('upload.html', output=None, filename=None, error=None)

@app.route('/upload', methods=['POST'])
@require_auth
def upload_install():
    file = request.files.get('package')
    if not file or file.filename == '':
        return render_template('upload.html', output=None, filename=None, error="No file selected.")

    if not allowed_file(file.filename):
        return render_template('upload.html', output=None, filename=None, error="Only .deb files are allowed.")

    os.makedirs('/tmp/deb-uploads', exist_ok=True)
    fname = secure_filename(file.filename)
    save_path = os.path.join('/tmp/deb-uploads', fname)
    file.save(save_path)

    # Install the package
    install_cmd = f"dpkg -i '{save_path}'"
    fix_cmd = "apt -f -y install"
    try:
        out1 = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        out2 = subprocess.run(fix_cmd, shell=True, capture_output=True, text=True)
        output = (
            f"$ {install_cmd}\n{out1.stdout}\n{out1.stderr}\n"
            f"$ {fix_cmd}\n{out2.stdout}\n{out2.stderr}\n"
        )
    except Exception as e:
        output = f"Installer crashed: {e}"

    return render_template('upload.html', output=output, filename=fname, error=None)

if __name__ == '__main__':
    if is_port_in_use(80, '127.0.0.1'):
        log("⚠️ Port 80 is already in use. Webserver already running. Exiting.")
        sys.exit(0)

    log("🚀 Launching Flask app with Waitress on port 80")
    serve(app, host='0.0.0.0', port=80)

