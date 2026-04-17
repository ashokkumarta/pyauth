from pyrate_limiter import Duration, Limiter, Rate, BucketFullException
import os

# Default configuration for rate limits, can be overridden by environment variable
RATE_LIMIT_CONFIG = 'RATE_LIMIT_CONFIG'
default_rate_limit_min = 5
default_rate_limit_hour = 100
default_rate_limit_day = 1000

__rate_limit_config = os.environ.get(RATE_LIMIT_CONFIG, f"{default_rate_limit_min},{default_rate_limit_hour},{default_rate_limit_day}").lower()

# validate __rate_limit_config
# split by comma and check if each value is int
if __rate_limit_config:
    rates_list = __rate_limit_config.split(',')
    if len(rates_list) == 3:
        try:
            rate_limit_min = int(rates_list[0])
            rate_limit_hour = int(rates_list[1])
            rate_limit_day = int(rates_list[2])
        except ValueError:
            # ignore... use default value
            pass

# set default value if invalid configuration provided
if rate_limit_min <= 0:
    rate_limit_min = default_rate_limit_min
if rate_limit_hour <= 0:
    rate_limit_hour = default_rate_limit_hour
if rate_limit_day <= 0:
    rate_limit_day = default_rate_limit_day

# Define limits: 5 requests per minute AND 100 requests per hour
rates = [
    Rate(rate_limit_min, Duration.MINUTE),
    Rate(rate_limit_hour, Duration.HOUR),
    Rate(rate_limit_day, Duration.DAY)
]

limiter = Limiter(rates)

def check_quota(user_id: str) -> tuple[bool, str]:
    try:
        limiter.try_acquire(user_id)
        # Proceed with your logic
        print("Request successful")
        return True, "Allowed"
    except BucketFullException as err:
        msg = f"Rate limit exceeded. Try again in {err.meta_info['wait_time']}s"
        print(msg)
        return False, msg
