"""
SentinelShield Web Application Firewall

The WAF acts as the security gateway between incoming
HTTP requests and the application.

Security checks:
1. Rate limiting
2. Attack signature detection
3. Security logging
4. Alert generation
"""

from detector import detect_attack
from logger import log_security_event, create_alert
from rate_limiter import check_rate_limit


# ============================================================
# REQUEST INSPECTION
# ============================================================

def inspect_request(request_data):

    ip_address = request_data.get(
        "ip_address",
        "Unknown"
    )

    path = request_data.get(
        "path",
        "Unknown"
    )

    # ========================================================
    # STEP 1 — RATE LIMIT CHECK
    # ========================================================

    rate_result = check_rate_limit(ip_address)

    if not rate_result["allowed"]:

        # Log rate-limit event
        log_security_event(
            ip_address=ip_address,
            attack_type="Rate Limit Violation",
            matched_pattern=(
                f"{rate_result['request_count']} requests "
                f"in {rate_result['window_seconds']} seconds"
            ),
            path=path,
            action="RATE_LIMIT",
            severity="MEDIUM"
        )

        # Create alert
        alert = create_alert(
            ip_address=ip_address,
            attack_type="Rate Limit Violation",
            path=path,
            severity="MEDIUM"
        )

        return {
            "allowed": False,
            "action": "RATE_LIMIT",
            "reason": "Request threshold exceeded",
            "matched_pattern": None,
            "severity": "MEDIUM",
            "rate_limit": rate_result,
            "alert": alert
        }

    # ========================================================
    # STEP 2 — ATTACK DETECTION
    # ========================================================

    result = detect_attack(request_data)

    if result["detected"]:

        # Log malicious request
        log_security_event(
            ip_address=ip_address,
            attack_type=result["attack_type"],
            matched_pattern=result["matched_pattern"],
            path=path,
            action="BLOCK",
            severity=result["severity"]
        )

        # Create security alert
        alert = create_alert(
            ip_address=ip_address,
            attack_type=result["attack_type"],
            path=path,
            severity=result["severity"]
        )

        return {
            "allowed": False,
            "action": "BLOCK",
            "reason": result["attack_type"],
            "matched_pattern": result["matched_pattern"],
            "severity": result["severity"],
            "rate_limit": rate_result,
            "alert": alert
        }

    # ========================================================
    # STEP 3 — REQUEST ALLOWED
    # ========================================================

    return {
        "allowed": True,
        "action": "ALLOW",
        "reason": None,
        "matched_pattern": None,
        "severity": "LOW",
        "rate_limit": rate_result,
        "alert": None
    }