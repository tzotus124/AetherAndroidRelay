import socket
import binascii
import threading
from flask import Flask, request, Response
from kivy.app import App
from kivy.uix.label import Label
from kivy.core.window import Window

app = Flask(__name__)
SECURITY_TOKEN = "AetherSecurePassphrase2026!"

@app.route('/wake', methods=['POST'])
def handle_wake():
    try:
        auth_key = request.headers.get('Authorization')
        target_mac = request.headers.get('Target-MAC')
        target_ip = request.headers.get('Target-IP')

        if not auth_key or not target_mac or not target_ip:
            return Response("Error: Missing dynamic pipeline headers.", status=400)
        if auth_key != SECURITY_TOKEN:
            return Response("Access Denied: Invalid Security token.", status=401)

        ip_parts = target_ip.strip().split('.')
        directed_broadcast_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255" if len(ip_parts) == 4 else "255.255.255.255"

        clean_mac = target_mac.replace(':', '').replace('-', '').replace(' ', '')
        hex_data = binascii.unhexlify(clean_mac)
        magic_packet = b'\xFF' * 6 + (hex_data * 16)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as lan_sock:
            lan_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            lan_sock.sendto(magic_packet, (directed_broadcast_ip, 9))
            lan_sock.sendto(magic_packet, ('255.255.255.255', 9))

        return Response("Tailscale Android routing verified. Physical WoL frame delivered cleanly.", status=200, mimetype='text/plain')
    except Exception as e:
        return Response(f"Internal processing error: {str(e)}", status=500)

def start_flask_engine():
    app.run(host='0.0.0.0', port=9999, debug=False, threaded=True)

class AetherRelayApp(App):
    def build(self):
        Window.clearcolor = (0.04, 0.05, 0.09, 1)
        threading.Thread(target=start_flask_engine, daemon=True).start()
        return Label(
            text="⚡ AETHER RELAY ONLINE\n\nServer Active on Port 9999\nEnsure Tailscale is On",
            font_size='18sp', halign='center', color=(0.22, 0.74, 0.97, 1)
        )

if __name__ == '__main__':
    AetherRelayApp().run()
