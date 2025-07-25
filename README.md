# Simple authentication server in flask for nginx
Uses a list of api keys (defined in a sqlite db at `~/.config/ongpi/api_keys.db`) to validate requests for nginx.

**Important**: nginx parses headers, so don't use `$` in `API-KEY` or `Authorization` headers as nginx will parse it and delete them 

## Nginx configuration
Define an `auth_request` directive for all locations to protect.

Don't forget `underscores_in_headers on;` directive in `server`section, to deal properly with `API-KEY`header
```
server {
            listen 443 ssl;
            server_name YOUR_SERVER_NAME;
            # Important! otherwise API-KEY won't be reconized
            underscores_in_headers on;


location /{
            auth_request /auth_api_key;
}


location /auth_api_key {
    # Replace your port with the appropiate one
    proxy_pass http://127.0.0.1:YOUR_PORT/auth_api_key;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
    # Login service returns a redirect to the original URI
    # and sets the cookie for the authenticator
    proxy_set_header Host $host:$server_port;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header x-api-key $http_api_key;
    proxy_set_header x-authorization $http_authorization;

}

}
```

## Adding users to api_keys.db

Passwords are hashed, so use the following code to add a user:
```python
from ong_auth_server.validate_keys import KeyValidator
# Initialize validator
validator = KeyValidator()
# Add some users
validator.add_user("admin", "secure_password_123")
```