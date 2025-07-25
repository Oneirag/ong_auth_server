import os
import secrets

import eventlet
from eventlet import wsgi
from flask import Flask, request, abort
from flask_ipban import IpBan
from validate_keys import validate_key
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(128)
ip_ban = IpBan(app, ip_header="X-Real-IP")


@app.route('/auth_api_key', methods=['GET', 'POST'])
def auth_api_key():
    # Obtenemos la clave API válida, bien via API-KEY o como Authorization header
    authorization = request.headers.get("X-AUTHORIZATION")
    if authorization and "Bearer " in authorization:
        authorization = authorization.split("Bearer ")[1]
    api_key_header = request.headers.get('X-API_KEY') or authorization
    if not api_key_header:
        ip_ban.add()
        return abort(401)

    # Verificamos si la clave API es válida en la base de datos
    if not validate_key(api_key_header):
        ip_ban.add()
        return abort(403)

    return "", 204


if __name__ == '__main__':
    wsgi.server(eventlet.listen(("127.0.0.1", os.getenv("ONG_AUTH_PORT", 8888)), app))

