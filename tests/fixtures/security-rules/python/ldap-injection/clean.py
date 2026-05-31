import ldap
from flask import request
from ldap.filter import escape_filter_chars

def find_user(conn):
    username = escape_filter_chars(request.args.get("user"))
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")
