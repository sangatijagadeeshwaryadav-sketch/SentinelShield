"""
SentinelShield
Detection Engine

The detection engine receives HTTP request data,
normalizes it, and compares it against the security
rules defined in rules.py.
"""

from rules import DETECTION_RULES


# ============================================================
# NORMALIZE REQUEST DATA
# ============================================================

def normalize_request_data(request_data):
    """
    Convert request information into a single lowercase string.

    This allows the detection engine to inspect different
    parts of a request together.
    """

    if request_data is None:
        return ""

    return str(request_data).lower()


# ============================================================
# DETECT ATTACK
# ============================================================

def detect_attack(request_data):
    """
    Compare request data against all SentinelShield rules.

    Returns a dictionary describing the detection result.
    """

    data = normalize_request_data(request_data)

    # Check every attack category
    for attack_type, patterns in DETECTION_RULES.items():

        # Check every pattern belonging to that category
        for pattern in patterns:

            if pattern.lower() in data:

                return {
                    "detected": True,
                    "attack_type": attack_type,
                    "matched_pattern": pattern,
                    "action": "BLOCK",
                    "severity": "HIGH"
                }

    # No suspicious pattern found
    return {
        "detected": False,
        "attack_type": None,
        "matched_pattern": None,
        "action": "ALLOW",
        "severity": "LOW"
    }


# ============================================================
# TEST DETECTOR DIRECTLY
# ============================================================

if __name__ == "__main__":

    test_requests = [
        "hello world",
        "' OR 1=1",
        "<script>alert(1)</script>",
        "../secret.txt",
        "/etc/passwd",
        "; whoami"
    ]

    print("\nSentinelShield Detection Engine Test")
    print("=" * 45)

    for test_request in test_requests:

        result = detect_attack(test_request)

        print(f"\nRequest: {test_request}")
        print(f"Detected: {result['detected']}")
        print(f"Attack: {result['attack_type']}")
        print(f"Matched Rule: {result['matched_pattern']}")
        print(f"Action: {result['action']}")
        print(f"Severity: {result['severity']}")