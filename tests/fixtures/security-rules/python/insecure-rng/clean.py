import secrets
def make_token():
    return secrets.token_hex(16)
