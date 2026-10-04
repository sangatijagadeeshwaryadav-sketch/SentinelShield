"""
SentinelShield Detection Accuracy Test

Measures:
- True Positives
- True Negatives
- False Positives
- False Negatives
- Detection Accuracy
"""

import os
import sys


# ============================================================
# ADD APP DIRECTORY TO PYTHON PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

APP_DIRECTORY = os.path.join(
    PROJECT_ROOT,
    "app"
)

sys.path.insert(
    0,
    APP_DIRECTORY
)


# Now we can import the detection engine
from detector import detect_attack


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    # Known attack patterns

    {
        "name": "SQL Injection",
        "input": "' OR 1=1",
        "expected_attack": True
    },

    {
        "name": "XSS",
        "input": "<script>alert(1)</script>",
        "expected_attack": True
    },

    {
        "name": "Path Traversal",
        "input": "../secret.txt",
        "expected_attack": True
    },

    {
        "name": "LFI",
        "input": "/etc/passwd",
        "expected_attack": True
    },

    {
        "name": "Command Injection",
        "input": "; whoami",
        "expected_attack": True
    },


    # Normal requests

    {
        "name": "Normal Greeting",
        "input": "hello world",
        "expected_attack": False
    },

    {
        "name": "Normal Search",
        "input": "cybersecurity internship",
        "expected_attack": False
    },

    {
        "name": "Normal Username",
        "input": "Jagadeesh123",
        "expected_attack": False
    },


    # Modified attack variants

    {
        "name": "SQLi Variant",
        "input": "UNION/**/SELECT",
        "expected_attack": True
    },

    {
        "name": "Command Variant",
        "input": "; uname",
        "expected_attack": True
    }
]


# ============================================================
# MAIN TEST
# ============================================================

def main():

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    print()
    print("=" * 75)
    print("          SENTINELSHIELD DETECTION ACCURACY TEST")
    print("=" * 75)

    print()

    print(
        f"{'TEST':<25}"
        f"{'EXPECTED':<12}"
        f"{'ACTUAL':<12}"
        f"RESULT"
    )

    print("-" * 75)

    for test in TEST_CASES:

        result = detect_attack(
            test["input"]
        )

        actual_attack = result["detected"]

        expected_attack = test["expected_attack"]


        # ----------------------------------------------------
        # CLASSIFY RESULT
        # ----------------------------------------------------

        if expected_attack and actual_attack:

            true_positive += 1
            classification = "TRUE POSITIVE"

        elif not expected_attack and not actual_attack:

            true_negative += 1
            classification = "TRUE NEGATIVE"

        elif not expected_attack and actual_attack:

            false_positive += 1
            classification = "FALSE POSITIVE"

        else:

            false_negative += 1
            classification = "FALSE NEGATIVE"


        expected_text = (
            "ATTACK"
            if expected_attack
            else "NORMAL"
        )

        actual_text = (
            "ATTACK"
            if actual_attack
            else "NORMAL"
        )


        print(
            f"{test['name']:<25}"
            f"{expected_text:<12}"
            f"{actual_text:<12}"
            f"{classification}"
        )


    # ========================================================
    # CALCULATE ACCURACY
    # ========================================================

    total_tests = len(TEST_CASES)

    accuracy = (
        (true_positive + true_negative)
        / total_tests
    ) * 100


    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 75)
    print("                     TEST SUMMARY")
    print("=" * 75)

    print(
        f"Total Tests       : {total_tests}"
    )

    print(
        f"True Positives    : {true_positive}"
    )

    print(
        f"True Negatives    : {true_negative}"
    )

    print(
        f"False Positives   : {false_positive}"
    )

    print(
        f"False Negatives   : {false_negative}"
    )

    print(
        f"Detection Accuracy: {accuracy:.2f}%"
    )

    print("=" * 75)
    print()


if __name__ == "__main__":
    main()