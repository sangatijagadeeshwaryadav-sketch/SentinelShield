"""
SentinelShield Final Validation Test

Validates the major components of the project:

1. Normal request handling
2. SQL Injection detection
3. XSS detection
4. Path Traversal detection
5. LFI detection
6. Command Injection detection
7. Security log generation

All tests target the local SentinelShield application.
"""

import os
import sys
import urllib.request
import urllib.error
import urllib.parse


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

LOG_FILE = os.path.join(
    PROJECT_ROOT,
    "logs",
    "security.log"
)


# ============================================================
# TEST SERVER
# ============================================================

BASE_URL = "http://127.0.0.1:5000/protected"


# ============================================================
# SEND LOCAL TEST REQUEST
# ============================================================

def send_request(test_name, payload):

    encoded_payload = urllib.parse.quote(
        payload,
        safe=""
    )

    url = f"{BASE_URL}?q={encoded_payload}"

    try:

        response = urllib.request.urlopen(
            url,
            timeout=5
        )

        status = response.status

    except urllib.error.HTTPError as error:

        status = error.code

    except Exception as error:

        print(
            f"{test_name:<25} ERROR: {error}"
        )

        return None


    if status == 200:

        result = "ALLOWED"

    elif status == 403:

        result = "BLOCKED"

    elif status == 429:

        result = "RATE LIMITED"

    else:

        result = f"HTTP {status}"


    print(
        f"{test_name:<25}"
        f"{status:<10}"
        f"{result}"
    )

    return status


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("             SENTINELSHIELD FINAL VALIDATION")
    print("=" * 70)

    print()

    print(
        f"{'TEST':<25}"
        f"{'STATUS':<10}"
        f"RESULT"
    )

    print("-" * 70)


    # --------------------------------------------------------
    # NORMAL REQUEST
    # --------------------------------------------------------

    normal_status = send_request(
        "Normal Request",
        "hello world"
    )


    # --------------------------------------------------------
    # SQL INJECTION
    # --------------------------------------------------------

    sql_status = send_request(
        "SQL Injection",
        "' OR 1=1"
    )


    # --------------------------------------------------------
    # XSS
    # --------------------------------------------------------

    xss_status = send_request(
        "XSS",
        "<script>alert(1)</script>"
    )


    # --------------------------------------------------------
    # PATH TRAVERSAL
    # --------------------------------------------------------

    traversal_status = send_request(
        "Path Traversal",
        "../secret.txt"
    )


    # --------------------------------------------------------
    # LFI
    # --------------------------------------------------------

    lfi_status = send_request(
        "LFI",
        "/etc/passwd"
    )


    # --------------------------------------------------------
    # COMMAND INJECTION
    # --------------------------------------------------------

    command_status = send_request(
        "Command Injection",
        "; whoami"
    )


    # ========================================================
    # EXPECTED RESULTS
    # ========================================================

    expected_results = {

        "Normal Request": normal_status == 200,

        "SQL Injection": sql_status == 403,

        "XSS": xss_status == 403,

        "Path Traversal": traversal_status == 403,

        "LFI": lfi_status == 403,

        "Command Injection": command_status == 403
    }


    passed = sum(
        expected_results.values()
    )

    total = len(expected_results)


    # ========================================================
    # LOG CHECK
    # ========================================================

    log_exists = os.path.exists(
        LOG_FILE
    )

    print()
    print("-" * 70)

    print(
        f"Security log exists : "
        f"{'YES' if log_exists else 'NO'}"
    )

    print(
        f"Tests passed        : "
        f"{passed}/{total}"
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()

    if passed == total and log_exists:

        print("FINAL RESULT: PASS")

        print(
            "SentinelShield successfully "
            "passed the core validation tests."
        )

    else:

        print("FINAL RESULT: REVIEW REQUIRED")

        print(
            "One or more validation tests "
            "did not produce the expected result."
        )


    print("=" * 70)
    print()


if __name__ == "__main__":

    main()