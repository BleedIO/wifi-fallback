# webserver.py

from flask import Flask, render_template, request, redirect, url_for
import os
import sys
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

@app.context_processor
def inject_hostname():
    return {"hostname": socket.gethostname()}

@app.route('/', methods=['GET', 'POST'])
def wifi():
    try:
        if request.method == 'POST':
            ssid = request.form['ssid']
            password = request.form['password']
            log(f"📥 Received credentials: SSID='{ssid}'")
            with open("/etc/wpa_supplicant/wpa_supplicant.conf", "w") as f:
                f.write(f'''
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    psk="{password}"
}}
''')
            os.system("sync")
            log("✅ Wi‑Fi credentials written and synced")
            return redirect(url_for('confirmation'))
        return render_template('index.html')
    except Exception:
        log("❌ Exception in `/` route:\n" + traceback.format_exc())
        return "Internal Server Error", 500

@app.route('/confirmation')
def confirmation():
    log("✅ Confirmation page displayed.")
    return render_template('confirmation.html')

# @app.route('/cancel')
# def cancel():
#     log("❌ Cancel requested. Shutting down AP...")
#     os.system("nmcli connection down Hotspot")
#     print("Hotspot stopped. You can now close this page.")  # to server stdout/log
#     return redirect(url_for('confirmation'))

@app.route('/status')
def status():
    log("📡 Status page requested.")
    result = subprocess.run(
        ["systemctl", "status", "rssi-gatewayapi.service", "--no-pager"],
        capture_output=True, text=True, check=False
    )
    return render_template('status.html', status=result.stdout)

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
