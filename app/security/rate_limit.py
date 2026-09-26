from collections import defaultdict, deque
from datetime import datetime, timedelta


MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
BLOCK_SECONDS = 60


_failed_attempts = defaultdict(deque)
_blocked_until = {}


def _now():
    return datetime.utcnow()


def is_login_blocked(key: str) -> bool:
    now = _now()

    blocked_until = _blocked_until.get(key)

    if blocked_until is None:
        return False

    if now >= blocked_until:
        del _blocked_until[key]
        return False

    return True


def register_failed_login(key: str) -> bool:
    now = _now()
    attempts = _failed_attempts[key]

    cutoff = now - timedelta(seconds=WINDOW_SECONDS)

    while attempts and attempts[0] < cutoff:
        attempts.popleft()

    attempts.append(now)

    if len(attempts) >= MAX_ATTEMPTS:
        _blocked_until[key] = now + timedelta(
            seconds=BLOCK_SECONDS
        )
        attempts.clear()
        return True

    return False


def clear_failed_logins(key: str):
    _failed_attempts.pop(key, None)
    _blocked_until.pop(key, None)