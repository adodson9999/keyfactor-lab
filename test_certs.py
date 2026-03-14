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

# Temporary OpenSSL config file used during cert generation
# This approach works on all platforms unlike the -subj flag
CONFIG_FILE = "openssl_keyfactor.cnf"

# How many days the generated certificate should be valid
CERT_VALIDITY_DAYS = 365

# How many days before expiry we consider a cert "expiring soon"
EXPIRY_WARNING_DAYS = 30

# The CA name our tests expect to find inside the certificate
# Must match the CN value in the config content below
EXPECTED_ISSUER = "KeyfactorLab-RootCA"

# Minimum acceptable RSA key size in bits
MIN_KEY_SIZE = 2048

# The OpenSSL config file content that defines the certificate fields
# Using a config file instead of -subj flag because Windows OpenSSL
# handles the -subj flag inconsistently across different builds
# CN = Common Name (the CA name), O = Organization, C = Country
OPENSSL_CONFIG = """
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
CN = KeyfactorLab-RootCA
O  = KeyfactorLab
C  = US

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
"""


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
    Generates a self-signed certificate using an OpenSSL config file.

    Why a config file instead of the -subj flag?
    The -subj flag (e.g. -subj '/CN=KeyfactorLab-RootCA') works fine on
    macOS and Linux but behaves inconsistently on Windows depending on which
    OpenSSL build is installed. Some Windows builds ignore the subject entirely,
    leaving the issuer field blank. Writing the subject fields to a config file
    and passing it with -config bypasses all shell escaping issues and works
    identically on every operating system.
    """
    current_os = detect_os()

    print(f"\n{'='*55}")
    print(f"  Keyfactor Lab — Certificate Test Suite")
    print(f"{'='*55}")
    print(f"  OS detected  : {current_os.upper()}")
    print(f"  Generating   : {CERT_FILE}")

    # Write the OpenSSL config to a temporary file on disk
    # OpenSSL reads this file to know what fields to put in the certificate
    with open(CONFIG_FILE, "w") as f:
        f.write(OPENSSL_CONFIG)

    # Build the OpenSSL command using -config instead of -subj
    # Every field (CN, O, C) comes from the config file — no shell escaping needed
    command = [
        "openssl", "req",
        "-x509",                            # make it self-signed (no external CA)
        "-newkey", "rsa:2048",              # generate a new 2048-bit RSA key pair
        "-keyout", KEY_FILE,                # save the private key to this file
        "-out", CERT_FILE,                  # save the certificate to this file
        "-days", str(CERT_VALIDITY_DAYS),   # how long the cert is valid
        "-nodes",                           # no password on the private key
        "-config", CONFIG_FILE              # read subject fields from config file
    ]

    # Run the OpenSSL command and capture all output for error reporting
    result = subprocess.run(command, capture_output=True, text=True)

    # Always clean up the temporary config file, even if generation failed
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)

    # A non-zero return code means OpenSSL failed — show the error clearly
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
        if os.path.exists(filename):        # only delete if the file exists
            os.remove(filename)             # permanently delete the file
            print(f"  Deleted: {filename}")


def load_cert(path):
    """
    Opens a .pem certificate file and returns a parsed certificate object.
    All test functions call this to load the cert they need to inspect.
    path: string file path to the certificate file
    """
    with open(path, "rb") as f:             # 'rb' = read binary — certs are binary
        return x509.load_pem_x509_certificate(f.read(), default_backend())


# ─────────────────────────────────────────────
# PYTEST FIXTURE — auto-runs before and after every test session
# ─────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_certificate():
    """
    A pytest fixture that runs automatically for every test session.

    BEFORE tests (setup):
      - Checks OpenSSL is installed
      - Generates the certificate and key files

    AFTER tests (teardown):
      - Deletes the certificate and key files

    scope='session'  = runs once per pytest session, not once per test
    autouse=True     = applies to all tests automatically, no need to reference it
    yield            = the dividing line between setup and teardown
    """

    # ── SETUP ─────────────────────────────────────────────────────

    # Verify OpenSSL is available before trying to use it
    if not check_openssl():
        raise RuntimeError(
            "\nOpenSSL not found. Please install it:\n"
            "  macOS  :  brew install openssl\n"
            "  Ubuntu :  sudo apt install openssl\n"
            "  Windows:  https://slproweb.com/products/Win32OpenSSL.html"
        )

    # Generate the certificate — all 5 tests depend on this file existing
    generate_cert()

    # ── TESTS RUN HERE ────────────────────────────────────────────
    yield
    # ── TEARDOWN ──────────────────────────────────────────────────

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
    broken logins, failed API calls. This is the most basic health check.
    """
    cert = load_cert(CERT_FILE)

    # The cert's expiry date must be later than right now
    assert cert.not_valid_after_utc > datetime.now(timezone.utc), \
        "FAIL: Certificate is already expired — immediate renewal required!"


def test_cert_issued_by_expected_ca():
    """
    TEST 2: Verify the cert was issued by our trusted CA.
    In PKI environments, every cert must trace back to a known, trusted
    Certificate Authority. An unexpected issuer is a red flag for
    misconfiguration or a security incident.

    We use rfc4514_string() to convert the issuer to a readable string
    and check that our CA name appears inside it. This is more reliable
    than get_attributes_for_oid() which fails on some Windows OpenSSL builds
    when the CN field list comes back empty.
    """
    cert = load_cert(CERT_FILE)

    # Convert the issuer to an RFC4514 string like "CN=KeyfactorLab-RootCA,O=KeyfactorLab,C=US"
    # This format is consistent and readable across all platforms
    issuer_string = cert.issuer.rfc4514_string()

    # Also check each attribute individually as a fallback
    # get_attributes_for_oid returns a list — we check if it's non-empty first
    cn_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

    if cn_attributes:
        # If CN attribute exists, verify it matches exactly
        assert cn_attributes[0].value == EXPECTED_ISSUER, \
            f"FAIL: CN is '{cn_attributes[0].value}' — expected '{EXPECTED_ISSUER}'"
    else:
        # Fallback: check the full issuer string contains our CA name
        assert EXPECTED_ISSUER in issuer_string, \
            f"FAIL: '{EXPECTED_ISSUER}' not found in issuer string: '{issuer_string}'"


def test_cert_key_size():
    """
    TEST 3: Verify the certificate uses a key of at least 2048 bits.
    Key size determines cryptographic strength. Keys below 2048 bits fail
    modern compliance standards (PCI-DSS, NIST) and are rejected by most
    browsers and operating systems.
    """
    cert = load_cert(CERT_FILE)

    # Extract the public key size in bits
    key_size = cert.public_key().key_size

    assert key_size >= MIN_KEY_SIZE, \
        f"FAIL: Key is {key_size} bits — minimum required is {MIN_KEY_SIZE} bits"


def test_cert_expiry_warning():
    """
    TEST 4: Warn if the certificate expires within 30 days.
    Certificate outages are almost always preventable — they happen because
    no one noticed the cert was about to expire. This test catches that
    window early so renewals happen before anything breaks.
    """
    cert = load_cert(CERT_FILE)

    # Calculate days remaining until expiry
    days_remaining = (
        cert.not_valid_after_utc - datetime.now(timezone.utc)
    ).days

    assert days_remaining > EXPIRY_WARNING_DAYS, \
        f"FAIL: Cert expiring in {days_remaining} days — renewal needed!"


def test_cert_validity_period():
    """
    TEST 5: Verify the certificate was issued for the correct number of days.
    Certs valid for too long are a security risk — a compromised key stays
    dangerous for the entire validity window. CA/Browser Forum rules cap
    public certs at 398 days. This test ensures our cert matches policy.
    """
    cert = load_cert(CERT_FILE)

    # Calculate total validity in days (end date minus start date)
    total_days = (
        cert.not_valid_after_utc - cert.not_valid_before_utc
    ).days

    # Allow 1 day buffer for timezone and rounding edge cases
    assert abs(total_days - CERT_VALIDITY_DAYS) <= 1, \
        f"FAIL: Cert is valid for {total_days} days — expected {CERT_VALIDITY_DAYS}"