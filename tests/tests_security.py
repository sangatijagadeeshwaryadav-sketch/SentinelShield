"""
SentinelShield Security Test Suite

Tests SentinelShield against normal traffic and
safe simulated attack patterns on the local lab server.
"""

import urllib.request
import urllib.error
import urllib.parse


BASE_URL = "http://127.0.0.1:5000/protected"


# ============================================================
# SEND REQUEST
# ============================================================

def send_test(name, parameter):

    encoded_parameter = urllib.parse.quote(
        parameter,
        safe=""
    )

    url = f"{BASE_URL}?q={encoded_parameter}"

    try:

        response = urllib.request.urlopen(
            url,
            timeout=5
        )

        status_code = response.status

    except urllib.error.HTTPError as error:

        status_code = error.code

    except Exception as error:

        print(f"{name:<25} ERROR: {error}")
        return

    if status_code == 200:

        result = "ALLOWED"

    elif status_code == 403:

        result = "BLOCKED"

    elif status_code == 429:

        result = "RATE LIMITED"

    else:

        result = f"HTTP {status_code}"

    print(
        f"{name:<25} "
        f"{status_code:<8} "
        f"{result}"
    )


# ============================================================
# MAIN TEST SUITE
# ============================================================

def main():

    print()
    print("=" * 65)
    print("        SENTINELSHIELD SECURITY TEST SUITE")
    print("=" * 65)

    print()
    print(
        f"{'TEST':<25} "
        f"{'STATUS':<8} "
        f"RESULT"
    )

    print("-" * 65)

    # --------------------------------------------------------
    # NORMAL REQUEST
    # --------------------------------------------------------

    send_test(
        "Normal Request",
        "hello world"
    )

    # --------------------------------------------------------
    # SQL INJECTION
    # --------------------------------------------------------

    send_test(
        "SQL Injection",
        "' OR 1=1"
    )

    # --------------------------------------------------------
    # XSS
    # --------------------------------------------------------

    send_test(
        "XSS",
        "<script>alert(1)</script>"
    )

    # --------------------------------------------------------
    # PATH TRAVERSAL
    # --------------------------------------------------------

    send_test(
        "Path Traversal",
        "../secret.txt"
    )

    # --------------------------------------------------------
    # LFI
    # --------------------------------------------------------

    send_test(
        "LFI",
        "/etc/passwd"
    )

    # --------------------------------------------------------
    # COMMAND INJECTION
    # --------------------------------------------------------

    send_test(
        "Command Injection",
        "; whoami"
    )

    print()
    print("=" * 65)
    print("Basic security testing completed.")
    print("=" * 65)
    print()


if __name__ == "__main__":

    main()