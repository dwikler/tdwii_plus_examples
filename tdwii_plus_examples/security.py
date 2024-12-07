# security.py

import ssl
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging


class SecurityProfile:
    SCP_ROLE = "SCP"  # Security Profile for a server
    SCU_ROLE = "SCU"  # Security Profile for a client

    ROLE_TO_PURPOSE = {
        SCP_ROLE: ssl.Purpose.CLIENT_AUTH,
        SCU_ROLE: ssl.Purpose.SERVER_AUTH
    }

    def __init__(self, ca_certificate, private_key, certificate, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        # Verify certificates and private key
        self._logger.debug("Initializing SecurityProfile instance")
        try:
            self._ca_cert_path = self._load_certificate(ca_certificate)
            self._cert_path = self._load_certificate(certificate)
            self._key_path = self._load_private_key(private_key)
            self._logger.debug("SecurityProfile initialization successful")
        except Exception as e:
            self._logger.error(f"Error during SecurityProfile initialization: {e}")
            raise

    def _load_certificate(self, cert_path):
        """Load and validate a certificate from a given path."""
        try:
            # Get absolute path, handling OS-specific differences
            path = Path(cert_path).resolve()
            self._logger.debug(f"Loading certificate from {path}")
            # Try to read the file and to load the certificate
            with open(path, "rb") as pem_file:
                pem_data = pem_file.read()
                cert_info = x509.load_pem_x509_certificate(pem_data)
                self._logger.debug("Certificate content:")
                self._logger.debug("  Subject: %s", cert_info.subject)
                self._logger.debug("  Issuer: %s", cert_info.issuer)
                self._logger.debug("  Validity Period: %s - %s", cert_info.not_valid_before_utc, cert_info.not_valid_after_utc)
            return path
        except Exception as e:
            self._logger.error(f"Error loading certificate from {cert_path}: {e}")
            raise

    def _load_private_key(self, key_path):
        """Load and validate a private key from a given path."""
        try:
            # Get absolute path, handling OS-specific differences
            path = Path(key_path).resolve()
            self._logger.debug(f"Loading private key from {path}")
            # Try to read the file and to load the key
            with open(path, "rb") as pem_file:
                pem_data = pem_file.read()
            private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
            key_type = type(private_key).__name__.replace("PrivateKey", "")
            self._logger.debug("Private key is %s-%s", key_type, private_key.key_size)
            return path
        except Exception as e:
            self._logger.error(f"Error loading certificate from {key_path}: {e}")
            raise

    def get_cert_fingerprint(cert):
        """Get SHA-256 fingerprint from a certificate."""
        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        return hashlib.sha256(der).hexdigest()

    def _verify_callback(self, conn, cert, errnum, depth, ok):
        """Verify peer certificate."""
        self._logger.debug("Verifying certificate")
        if not preverify_ok:
            return False
        self._logger.debug("  Subject: %s", cert.subject)
        self._logger.debug("  Issuer: %s", cert.issuer)
        self._logger.debug("  Validity Period: %s - %s", cert.not_valid_before_utc, cert.not_valid_after_utc)
        # Optionally we could add verification of known nodes instead of allowing all from the trusted CA
        # fingerprint = _get_cert_fingerprint(cert)
        # self._logger.debug("  SHA-256 Fingerprint: %s", fingerprint)
        # Load allowed fingerprints from a configuration file or PEM file
        #allowed_fingerprints = load_allowed_fingerprints('allowed_certs.pem')
        # Check if the fingerprint is in the list of allowed fingerprints
        #if fingerprint not in allowed_fingerprints:
        #    return False
        return True

    def get_profile(self, role):
        ssl_cx = None
        try:
            # Create the  SSLContext
            self._logger.debug("Creating SSL Context")
            purpose = self.ROLE_TO_PURPOSE.get(role)
            if purpose is None:
                raise ValueError("Invalid role. Use SecurityProfile.SCP_ROLE for a server or SecurityProfile.SCU_ROLE for a client.")
            ssl_cx = ssl.create_default_context(purpose)

            # Set the trusted CA certificate
            ssl_cx.load_verify_locations(cafile=self._ca_cert_path)

            # Activate mutual TLS (mTLS) mode, requiring client certificates for authentication
            self._logger.debug("Activated mutual authentication")
            ssl_cx.verify_mode = ssl.CERT_REQUIRED

            # Set our certificate and private key
            ssl_cx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)

            # Set the minimum and maximum allowed TLS versions
            self._logger.debug("Setting minimum TLS version to TLS 1.2")
            ssl_cx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._logger.debug("Setting maximum TLS version to TLS 1.3")
            ssl_cx.maximum_version = ssl.TLSVersion.TLSv1_3
        except (ssl.SSLError, IOError) as e:
            raise

        return ssl_cx
