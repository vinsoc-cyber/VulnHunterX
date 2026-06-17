from aiohttp_session.redis_storage import RedisStorage


def make_storage(redis):
    # httponly=False exposes the session cookie to JavaScript.
    return RedisStorage(redis, httponly=False)
