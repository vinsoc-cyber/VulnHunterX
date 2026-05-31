import logging
from flask import make_response

def handler():
    try:
        do_work()
    except Exception:
        logging.exception("work failed")
        return make_response("Internal Server Error", 500)
