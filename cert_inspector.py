# Import the x509 module to parse and read certificate data (structure, fields, dates)
from cryptography import x509

# Import the backend that handles low-level cryptographic operations
from cryptography.hazmat.backends import default_backend

# Import datetime and timezone to compare cert expiry dates against today's date
from datetime import datetime, timezone


def inspect_certificate(cert_path):
    """
    Opens a certificate file from disk, parses it, and prints key details.
    This simulates what a QA analyst would check when validating a cert.
    cert_path: the file path string pointing to a .pem certificate file
    """

    # Open the certificate file in binary mode ('rb') — PEM/DER files are binary
    with open(cert_path, "rb") as f:
        cert_data = f.read()  # Read all the raw bytes of the certificate file

    # Parse the raw bytes into a structured certificate object we can inspect
    # default_backend() tells the library which crypto engine to use (OpenSSL under the hood)
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Get the current time with timezone info — needed to compare against cert dates
    now = datetime.now(timezone.utc)

    # Calculate how many days remain until the cert expires
    # not_valid_after_utc is the cert's expiry date stored as a UTC datetime
    days_remaining = (cert.not_valid_after_utc - now).days

    # Print the entity the cert was issued to (e.g. the server or user name)
    print(f"Subject:        {cert.subject}")

    # Print who issued/signed this certificate (e.g. KeyfactorLab-RootCA)
    print(f"Issuer:         {cert.issuer}")

    # Print the date the certificate became valid
    print(f"Valid From:     {cert.not_valid_before_utc}")

    # Print the date the certificate will expire
    print(f"Expires:        {cert.not_valid_after_utc}")

    # Print the number of days left — critical for catching near-expiry certs
    print(f"Days Remaining: {days_remaining}")

    # Print a warning if cert expires within 30 days, otherwise show as valid
    # This mimics what tools like Keyfactor Command flag automatically
    print(f"Status:         {'⚠️  EXPIRING SOON' if days_remaining < 30 else '✅ Valid'}")


# Entry point — call the function with your exported cert file path
inspect_certificate("my_cert.pem")