"""
Point d'entrée Veridoc avec SocketIO.

Deux modes :
  1. Sans HTTPS (dev rapide) :
        python run.py
  2. Avec HTTPS (recommandé) :
        python run.py --https
"""
import os
import sys

from app import create_app
from app.extensions import socketio

app = create_app()


if __name__ == "__main__":
    use_https = "--https" in sys.argv

    ssl_context = None
    if use_https:
        cert = "dev-cert.pem"
        key  = "dev-key.pem"
        if not (os.path.exists(cert) and os.path.exists(key)):
            print(f"❌ Certificats introuvables : {cert}, {key}")
            print("   Génère-les avec :")
            print("   > mkcert -key-file dev-key.pem -cert-file dev-cert.pem "
                  "localhost 127.0.0.1 ::1")
            sys.exit(1)
        ssl_context = (cert, key)
        print("🔒 HTTPS activé (https://127.0.0.1:5000)")
    else:
        print("⚠️  HTTP simple (http://127.0.0.1:5000)")
        print("   Pour HTTPS : python run.py --https")

    # SocketIO.run() remplace app.run()
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=True,
        ssl_context=ssl_context,
        allow_unsafe_werkzeug=True,   # requis pour dev avec SocketIO
    )