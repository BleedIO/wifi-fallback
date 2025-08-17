# webserver.py

from flask import Flask, render_template, request, redirect, url_for
import os
import sys
import json
import traceback
from waitress import serve
import socket
import subprocess  # ✅ Add this at the top with other imports
from werkzeug.utils import secure_filename

LOG_FILE = "/tmp/wifi-fallback-web.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")
    print(msg)

log("🔧 Starting Wi-Fi Config Web Server...")

app = Flask(__name__, template_folder='templates')
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
    return {"hostname": socket.gethostname()}

@app.route('/', methods=['GET', 'POST'])
def wifi():
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
        return render_template('index.html', networks=networks)
    except Exception:
        log("❌ Exception in `/` route:\n" + traceback.format_exc())
        return "Internal Server Error", 500

@app.route('/status')
def status():
    try:
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
        log("❌ Exception in `/status` route:\n" + traceback.format_exc())
        return "Internal Server Error", 500

@app.route('/confirmation')
def confirmation():
    log("✅ Confirmation page displayed.")
    return render_template('confirmation.html')

@app.route('/cancel', methods=['POST'])
def cancel():
    log("❌ Shut down AP...")
    os.system("nmcli connection down Hotspot")
    print("Hotspot stopped. You can now close this page.")  # to server stdout/log
    #return redirect(url_for('confirmation'))

@app.route('/reboot', methods=['GET'])
def reboot_get():
    return "Method Not Allowed", 405

@app.route('/reboot', methods=['POST'])
def reboot():
    log("🔁 Reboot triggered from web")
    os.system("reboot")
    print("Rebooting...")
    return "Rebooting…", 200

@app.route('/upload', methods=['GET'])
def upload_form():
    return render_template('upload.html', output=None, filename=None, error=None)

@app.route('/upload', methods=['POST'])
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
