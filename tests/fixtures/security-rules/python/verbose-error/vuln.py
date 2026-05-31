import traceback
from flask import make_response

def handler():
    try:
        do_work()
    except Exception:
        return make_response(traceback.format_exc(), 500)
