import os
from flask import Flask, render_template, request

app = Flask(__name__, template_folder='templates')

@app.route('/', methods=['GET', 'POST'])
def wifi():
    if request.method == 'POST':
        ssid = request.form['ssid']
        password = request.form['password']
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
        return "<h3>✅ Saved. Rebooting...</h3><script>setTimeout(() => fetch('/reboot'), 1000)</script>"
    return render_template('index.html')

@app.route('/reboot')
def reboot():
    os.system("reboot")
    return "Rebooting..."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

