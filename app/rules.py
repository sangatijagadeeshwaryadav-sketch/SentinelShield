"""
SentinelShield
Security Detection Rules

This file contains the patterns used by SentinelShield
to identify potentially malicious HTTP requests.

These rules are intended for testing inside our local
SentinelShield laboratory application.
"""


# ============================================================
# SQL INJECTION RULES
# ============================================================

SQL_INJECTION_PATTERNS = [
    "' or '1'='1",
    "' or 1=1",
    "or 1=1",
    "union select",
    "select * from",
    "drop table",
    "insert into",
    "delete from",
]


# ============================================================
# CROSS-SITE SCRIPTING (XSS) RULES
# ============================================================

XSS_PATTERNS = [
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "<iframe",
]


# ============================================================
# PATH TRAVERSAL RULES
# ============================================================

PATH_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "%2e%2e\\",
]


# ============================================================
# LOCAL FILE INCLUSION (LFI) RULES
# ============================================================

LFI_PATTERNS = [
    "/etc/passwd",
    "etc/passwd",
    "boot.ini",
]


# ============================================================
# COMMAND INJECTION RULES
# ============================================================

COMMAND_INJECTION_PATTERNS = [
    "; whoami",
    "; id",
    "| whoami",
    "| id",
    "&& whoami",
    "&& id",
]


# ============================================================
# COMBINED RULE DATABASE
# ============================================================

DETECTION_RULES = {
    "SQL Injection": SQL_INJECTION_PATTERNS,
    "Cross-Site Scripting (XSS)": XSS_PATTERNS,
    "Path Traversal": PATH_TRAVERSAL_PATTERNS,
    "Local File Inclusion (LFI)": LFI_PATTERNS,
    "Command Injection": COMMAND_INJECTION_PATTERNS,
}