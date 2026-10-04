"""
SentinelShield Rate Limiter

This module monitors the number of requests received
from each IP address during a defined time window.

It helps detect excessive or automated traffic.
"""

import time


# ============================================================
# RATE LIMIT CONFIGURATION
# ============================================================

MAX_REQUESTS = 10
TIME_WINDOW = 30


# ============================================================
# REQUEST HISTORY
# ============================================================

request_history = {}


# ============================================================
# CHECK RATE LIMIT
# ============================================================

def check_rate_limit(ip_address):
    """
    Check whether an IP address has exceeded
    the allowed request threshold.

    Returns:
        allowed       -> True/False
        request_count -> Number of recent requests
        remaining     -> Remaining requests
    """

    current_time = time.time()

    # Create history for a new IP
    if ip_address not in request_history:
        request_history[ip_address] = []

    # Get existing request timestamps
    timestamps = request_history[ip_address]

    # Remove timestamps outside the time window
    timestamps = [
        timestamp
        for timestamp in timestamps
        if current_time - timestamp < TIME_WINDOW
    ]

    # Add current request
    timestamps.append(current_time)

    # Save updated history
    request_history[ip_address] = timestamps

    request_count = len(timestamps)

    # Check threshold
    if request_count > MAX_REQUESTS:

        return {
            "allowed": False,
            "request_count": request_count,
            "remaining": 0,
            "limit": MAX_REQUESTS,
            "window_seconds": TIME_WINDOW
        }

    return {
        "allowed": True,
        "request_count": request_count,
        "remaining": MAX_REQUESTS - request_count,
        "limit": MAX_REQUESTS,
        "window_seconds": TIME_WINDOW
    }