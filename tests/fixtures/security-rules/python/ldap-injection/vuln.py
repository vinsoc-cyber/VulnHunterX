import ldap
from flask import request

def find_user(conn):
    username = request.args.get("user")
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")
