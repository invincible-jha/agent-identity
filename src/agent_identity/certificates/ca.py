"""Certificate Authority for development and enterprise deployments.

Provides a self-signed CA that can issue agent certificates. Intended for
development and internal deployments; production use should substitute an
enterprise PKI CA via the sign_agent_cert interface.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from agent_identity.certificates.agent_cert import AgentCertificate


@dataclass
class CertificateAuthority:
    """Self-signed Certificate Authority for agent certificate issuance.

    Parameters
    ----------
    ca_cert:
        The CA's own X.509 certificate.
    ca_key:
        The CA's RSA private key.
    common_name:
        Human-readable name for this CA (used in subject).
    organization:
        Organization that owns this CA.
    """

    ca_cert: x509.Certificate
    ca_key: RSAPrivateKey
    common_name: str
    organization: str

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def generate_ca(
        cls,
        common_name: str = "Agent Identity CA",
        organization: str = "MuVeraAI",
        validity_days: int = 3650,
        ca_key_size: int = 3072,
    ) -> "CertificateAuthority":
        """Generate a new self-signed Certificate Authority.

        Creates an RSA key pair and issues a self-signed CA certificate
        valid for *validity_days* days. The default key size is 3072 bits,
        which meets NIST SP 800-57 recommendations for certificates with
        long validity periods (up to 10 years). Use 4096 for the highest
        security margin at the cost of slower key generation.

        Agent certificates issued by this CA use 2048-bit keys by default
        (shorter validity, lower risk profile) — see
        :meth:`sign_agent_cert` / :class:`AgentCertificate`.

        Parameters
        ----------
        common_name:
            Common name for the CA certificate subject.
        organization:
            Organization name for the CA certificate subject.
        validity_days:
            How long the CA certificate should be valid (default 10 years).
        ca_key_size:
            RSA key size in bits for the CA key pair. Defaults to 3072.
            Must be at least 2048; 3072 or 4096 recommended for long-lived CAs.

        Returns
        -------
        CertificateAuthority
            Fully initialized CA instance.

        Raises
        ------
        ValueError
            If ``ca_key_size`` is less than 2048.
        """
        if ca_key_size < 2048:
            raise ValueError(
                f"ca_key_size must be at least 2048 bits, got {ca_key_size}"
            )
        ca_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=ca_key_size,
        )

        now = datetime.datetime.now(datetime.timezone.utc)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            ]
        )

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        return cls(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name=common_name,
            organization=organization,
        )

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def sign_agent_cert(
        self,
        agent_id: str,
        organization: str,
        capabilities: list[str],
        trust_level: int,
        validity_days: int = 365,
    ) -> AgentCertificate:
        """Issue a signed certificate for an agent.

        Parameters
        ----------
        agent_id:
            Unique identifier for the agent.
        organization:
            Owning organization or namespace.
        capabilities:
            List of capability strings to encode in the certificate.
        trust_level:
            Integer trust level (0-4).
        validity_days:
            Certificate validity period in days.

        Returns
        -------
        AgentCertificate
            Signed certificate with PEM-encoded cert and key.
        """
        return AgentCertificate.generate(
            agent_id=agent_id,
            organization=organization,
            capabilities=capabilities,
            trust_level=trust_level,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            validity_days=validity_days,
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def ca_cert_pem(self) -> bytes:
        """Return PEM-encoded CA certificate bytes."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def ca_key_pem(self) -> bytes:
        """Return PEM-encoded CA private key bytes (unencrypted)."""
        return self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, cert_pem: bytes, key_pem: bytes) -> "CertificateAuthority":
        """Reconstruct a CertificateAuthority from PEM-encoded bytes.

        Parameters
        ----------
        cert_pem:
            PEM-encoded CA certificate.
        key_pem:
            PEM-encoded CA private key (unencrypted).

        Returns
        -------
        CertificateAuthority
            Reconstructed instance.
        """
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate

        ca_cert = load_pem_x509_certificate(cert_pem)
        ca_key = load_pem_private_key(key_pem, password=None)
        if not isinstance(ca_key, RSAPrivateKey):
            raise TypeError("CA key must be an RSA private key")

        cn_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

        common_name = cn_attrs[0].value if cn_attrs else "Agent Identity CA"
        organization = org_attrs[0].value if org_attrs else "Unknown"

        return cls(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name=str(common_name),
            organization=str(organization),
        )
