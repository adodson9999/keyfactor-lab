"""
test_certs.py — Keyfactor Lab: Self-Contained Certificate Test Suite
=====================================================================
This script does everything automatically:
  1. Detects what operating system it is running on
  2. Checks that OpenSSL is installed and available
  3. Generates a real self-signed certificate using OpenSSL
  4. Runs 5 automated pytest tests against that certificate
  5. Deletes the generated cert and key files after tests finish

Run with: pytest test_certs.py -v
Works on: macOS, Windows, Linux, and inside virtual machines
"""

# subprocess lets us run terminal commands (like openssl) from inside Python
import subprocess

# os gives us file system access — used to check if files exist and delete them
import os

# platform detects the operating system this script is running on
import platform

# shutil.which checks if a program is installed (like 'which openssl' in Terminal)
import shutil

# pytest is the testing framework — it finds and runs functions starting with test_
import pytest

# x509 parses certificate files so we can read their fields and values
from cryptography import x509

# default_backend provides the cryptographic engine that processes cert data
from cryptography.hazmat.backends import default_backend

# datetime and timezone let us compare the cert's expiry date against today
from datetime import datetime, timezone


# ─────────────────────────────────────────────
# CONFIGURATION — edit these values if needed
# ─────────────────────────────────────────────

# File name the generated certificate will be saved as
CERT_FILE = "my_cert.pem"

# File name the generated private key will be saved as
KEY_FILE = "my_key.pem"

# How many days the generated certificate should be valid
CERT_VALIDITY_DAYS = 365

# The identity info embedded inside the certificate
# CN = Common Name (CA name), O = Organization, C = Country
CERT_SUBJECT = "/CN=KeyfactorLab-RootCA/O=KeyfactorLab/C=US"

# How many days before expiry we consider a cert "expiring soon"
EXPIRY_WARNING_DAYS = 30

# The CA name our tests expect to find inside the certificate
EXPECTED_ISSUER = "KeyfactorLab-RootCA"

# Minimum acceptable RSA key size in bits
MIN_KEY_SIZE = 2048


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def detect_os():
    """
    Returns the current operating system as a simple lowercase string.
    platform.system() returns 'Darwin' for macOS, 'Windows', or 'Linux'.
    We normalize to lowercase so comparisons are consistent.
    """
    system = platform.system().lower()
    if system == "darwin":
        return "macos"      # Apple macOS
    elif system == "windows":
        return "windows"    # Microsoft Windows (including inside a VM)
    else:
        return "linux"      # Ubuntu, Debian, CentOS, etc.


def check_openssl():
    """
    Checks whether OpenSSL is installed and findable on this machine.
    shutil.which() searches the system PATH — same as typing 'which openssl'
    in Terminal. Returns True if found, False if not installed.
    """
    return shutil.which("openssl") is not None


def generate_cert():
    """
    Runs the OpenSSL command to generate a self-signed certificate.
    Uses subprocess to call OpenSSL exactly as you would in the terminal.
    Saves two files: CERT_FILE (the certificate) and KEY_FILE (the private key).
    Raises a RuntimeError with a clear message if generation fails.
    """
    current_os = detect_os()

    print(f"\n{'='*55}")
    print(f"  Keyfactor Lab — Certificate Test Suite")
    print(f"{'='*55}")
    print(f"  OS detected  : {current_os.upper()}")
    print(f"  Generating   : {CERT_FILE}")

    # Build the OpenSSL command as a list — safer than a single string
    # Each item is one part of the command, just like typing it in Terminal
    command = [
        "openssl", "req",       # certificate request operation
        "-x509",                # make it self-signed (no external CA needed)
        "-newkey", "rsa:2048",  # generate a new 2048-bit RSA key pair
        "-keyout", KEY_FILE,    # save the private key to this file
        "-out", CERT_FILE,      # save the certificate to this file
        "-days", str(CERT_VALIDITY_DAYS),  # how long the cert is valid
        "-nodes",               # no password on the private key (easier for testing)
        "-subj", CERT_SUBJECT   # the identity info to embed in the cert
    ]

    # Windows sometimes needs forward slashes escaped in the subject string
    if current_os == "windows":
        command[-1] = CERT_SUBJECT.replace("/", "//")

    # Run the command — capture output so errors display cleanly
    result = subprocess.run(command, capture_output=True, text=True)

    # A non-zero return code means OpenSSL encountered an error
    if result.returncode != 0:
        raise RuntimeError(
            f"\nOpenSSL failed (exit code {result.returncode}):\n{result.stderr}"
        )

    print(f"  Certificate  : created ✓")
    print(f"  Private key  : created ✓")
    print(f"{'='*55}\n")


def delete_cert_files():
    """
    Deletes the generated certificate and key files from disk.
    Called automatically after all tests finish to keep the folder clean
    and avoid leaving sensitive private key files sitting around.
    """
    for filename in [CERT_FILE, KEY_FILE]:
        if os.path.exists(filename):       # only delete if the file actually exists
            os.remove(filename)            # permanently delete the file
            print(f"  Deleted: {filename}")


def load_cert(path):
    """
    Opens a .pem certificate file and returns a parsed certificate object.
    All test functions below call this to get the cert they need to inspect.
    path: string file path to the certificate file
    """
    with open(path, "rb") as f:           # 'rb' = read binary — certs are binary files
        return x509.load_pem_x509_certificate(f.read(), default_backend())


# ─────────────────────────────────────────────
# PYTEST FIXTURE — auto-runs before and after every test session
# ─────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_certificate():
    """
    A pytest fixture that:
      - Runs ONCE before the first test (generates the certificate)
      - Runs ONCE after the last test (deletes the certificate files)

    'scope=session' means it runs once per pytest session, not once per test.
    'autouse=True' means every test uses this fixture automatically — no need
    to manually reference it in each test function.

    The 'yield' keyword is the dividing line:
      - Everything BEFORE yield = setup (runs before tests)
      - Everything AFTER yield = teardown (runs after tests finish)
    """

    # ── SETUP: runs before any tests ──────────────────────────────

    # First check that OpenSSL is available on this machine
    if not check_openssl():
        raise RuntimeError(
            "\nOpenSSL not found. Please install it:\n"
            "  macOS  :  brew install openssl\n"
            "  Ubuntu :  sudo apt install openssl\n"
            "  Windows:  https://slproweb.com/products/Win32OpenSSL.html"
        )

    # Generate the certificate — all tests depend on this file existing
    generate_cert()

    # ── Hand control over to the tests ────────────────────────────
    yield
    # ── TEARDOWN: runs after all tests finish ──────────────────────

    print(f"\n{'='*55}")
    print("  Cleaning up generated files...")
    delete_cert_files()
    print(f"{'='*55}\n")


# ─────────────────────────────────────────────
# TEST FUNCTIONS
# ─────────────────────────────────────────────

def test_cert_not_expired():
    """
    TEST 1: Verify the certificate has not already expired.
    An expired cert causes immediate failures everywhere — SSL errors,
    broken logins, failed API calls. This is the first thing to check.
    """
    cert = load_cert(CERT_FILE)

    # The cert's expiry date must be in the future (greater than right now)
    assert cert.not_valid_after_utc > datetime.now(timezone.utc), \
        "FAIL: Certificate is already expired — immediate renewal required!"


def test_cert_issued_by_expected_ca():
    """
    TEST 2: Verify the cert was issued by our trusted CA.
    In PKI environments, every cert must come from a known, trusted authority.
    A cert from an unexpected issuer is a red flag for misconfiguration or
    a security incident — exactly what Keyfactor monitors for.
    """
    cert = load_cert(CERT_FILE)

    # Extract the Common Name (CN) from the issuer field
    # CN is the human-readable name of the CA that signed this certificate
    issuer = cert.issuer.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )[0].value

    assert issuer == EXPECTED_ISSUER, \
        f"FAIL: Issued by '{issuer}' — expected '{EXPECTED_ISSUER}'"


def test_cert_key_size():
    """
    TEST 3: Verify the certificate uses a key of at least 2048 bits.
    Key size determines how hard the cert is to break cryptographically.
    Keys below 2048 bits fail modern compliance standards (PCI-DSS, NIST)
    and are rejected by most browsers and operating systems today.
    """
    cert = load_cert(CERT_FILE)

    # Extract the public key size in bits from the certificate
    key_size = cert.public_key().key_size

    assert key_size >= MIN_KEY_SIZE, \
        f"FAIL: Key is {key_size} bits — minimum required is {MIN_KEY_SIZE} bits"


def test_cert_expiry_warning():
    """
    TEST 4: Warn if the certificate expires within 30 days.
    Certificate outages are almost always preventable — they happen because
    no one noticed a cert was about to expire. This test catches that window
    early. Keyfactor Command automates this monitoring at enterprise scale.
    """
    cert = load_cert(CERT_FILE)

    # Calculate days remaining until the certificate expires
    days_remaining = (
        cert.not_valid_after_utc - datetime.now(timezone.utc)
    ).days

    assert days_remaining > EXPIRY_WARNING_DAYS, \
        f"FAIL: Cert expiring in {days_remaining} days — renewal needed!"


def test_cert_validity_period():
    """
    TEST 5: Verify the certificate was issued for the correct number of days.
    Certs valid for too long (e.g. 10 years) are a security risk — they give
    attackers a larger window if a key is compromised. CA/Browser Forum rules
    cap public certs at 398 days. This confirms our cert matches policy.
    """
    cert = load_cert(CERT_FILE)

    # Calculate total days between the cert's start date and end date
    total_days = (
        cert.not_valid_after_utc - cert.not_valid_before_utc
    ).days

    # Allow a 1-day buffer for timezone and rounding differences
    assert abs(total_days - CERT_VALIDITY_DAYS) <= 1, \
        f"FAIL: Cert is valid for {total_days} days — expected {CERT_VALIDITY_DAYS}"