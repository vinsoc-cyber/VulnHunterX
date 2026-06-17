from aiohttp_session.redis_storage import RedisStorage


def make_storage(redis):
    # Secure defaults: not readable by JS, only sent over HTTPS.
    return RedisStorage(redis, httponly=True, secure=True)
