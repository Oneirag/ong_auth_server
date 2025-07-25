import os
import secrets

import eventlet
from eventlet import wsgi
from flask import Flask, request, abort
from flask_ipban import IpBan
from ong_auth_server.validate_keys import KeyValidator
from ong_auth_server import AUTH_HEADER, API_KEY_HEADER

key_validator = KeyValidator("~/.config/ongpi/api_keys.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(128)
ip_ban = IpBan(app, ip_header="X-Real-IP")


@app.route('/auth_api_key', methods=['GET', 'POST'])
def auth_api_key():
    # Obtenemos la clave API válida, bien via API-KEY o como Authorization header
    authorization = request.headers.get(AUTH_HEADER)
    if authorization and "Bearer " in authorization:
        authorization = authorization.split("Bearer ")[1]
    else:
        authorization = ""
    api_key_header = request.headers.get(API_KEY_HEADER) or authorization
    if not api_key_header:
        ip_ban.add()
        return abort(401)

    # Verificamos si la clave API es válida en la base de datos
    if not key_validator.validate_key(api_key_header):
        ip_ban.add()
        return abort(403)

    return "", 204


if __name__ == '__main__':
    socket = eventlet.listen(("127.0.0.1", int(os.getenv("ONG_AUTH_PORT", 8888))))
    wsgi.server(socket, app)

