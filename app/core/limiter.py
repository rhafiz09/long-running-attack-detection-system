from slowapi import Limiter
from slowapi.util import get_remote_address

# Shared SlowAPI Rate Limiter instance keyed by remote client IP address
limiter = Limiter(key_func=get_remote_address)
