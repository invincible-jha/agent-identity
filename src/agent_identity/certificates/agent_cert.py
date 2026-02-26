"""Agent certificate dataclass and X.509 generation.

Each agent in the system holds an X.509 certificate that encodes its
identity, capabilities, trust level, and organizational affiliation.
Agent-specific metadata is stored in Subject Alternative Name (SAN)
extensions using URI-encoded values.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID


@dataclass
class AgentCertificate:
    """Represents a signed X.509 certificate for an AI agent.

    Parameters
    ----------
    agent_id:
        Globally unique identifier for the agent.
    organization:
        Owning organization or deployment namespace.
    capabilities:
        List of capability strings the agent is authorized to exercise.
    trust_level:
        Integer trust level (0-4) baked into the certificate at issuance.
    cert_pem:
        PEM-encoded X.509 certificate bytes.
    key_pem:
        PEM-encoded RSA private key bytes (may be empty if stored separately).
    serial_number:
        Certificate serial number as an integer.
    not_before:
        Certificate validity start.
    not_after:
        Certificate validity end.
    """

    agent_id: str
    organization: str
    capabilities: list[str]
    trust_level: int
    cert_pem: bytes
    key_pem: bytes
    serial_number: int
    not_before: datetime.datetime
    not_after: datetime.datetime

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def generate(
        cls,
        agent_id: str,
        organization: str,
        capabilities: list[str],
        trust_level: int,
        ca_cert: x509.Certificate,
        ca_key: RSAPrivateKey,
        validity_days: int = 365,
    ) -> "AgentCertificate":
        """Generate a new agent certificate signed by the given CA.

        Agent metadata is encoded in Subject Alternative Name extensions
        as RFC 3986 URI values so that standard X.509 tooling can parse
        the certificate without custom extensions.

        Parameters
        ----------
        agent_id:
            Unique identifier for the agent.
        organization:
            Owning organization.
        capabilities:
            List of capability strings.
        trust_level:
            Integer trust level between 0 and 4.
        ca_cert:
            The CA's X.509 certificate used for signing.
        ca_key:
            The CA's private key used for signing.
        validity_days:
            How many days the certificate should be valid.

        Returns
        -------
        AgentCertificate
            Fully populated dataclass with PEM-encoded cert and key.
        """
        agent_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now
        not_after = now + datetime.timedelta(days=validity_days)

        caps_encoded = ",".join(capabilities) if capabilities else ""

        san_uris: list[x509.GeneralName] = [
            x509.UniformResourceIdentifier(f"agent-identity://agent-id/{agent_id}"),
            x509.UniformResourceIdentifier(f"agent-identity://org/{organization}"),
            x509.UniformResourceIdentifier(f"agent-identity://trust-level/{trust_level}"),
            x509.UniformResourceIdentifier(f"agent-identity://capabilities/{caps_encoded}"),
        ]

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(san_uris), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        cert = builder.sign(ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cls(
            agent_id=agent_id,
            organization=organization,
            capabilities=capabilities,
            trust_level=trust_level,
            cert_pem=cert_pem,
            key_pem=key_pem,
            serial_number=cert.serial_number,
            not_before=not_before,
            not_after=not_after,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def load_x509(self) -> x509.Certificate:
        """Parse and return the X.509 certificate object."""
        from cryptography.x509 import load_pem_x509_certificate

        return load_pem_x509_certificate(self.cert_pem)

    def is_expired(self) -> bool:
        """Return True if the certificate has passed its not_after date."""
        return datetime.datetime.now(datetime.timezone.utc) > self.not_after

    def days_remaining(self) -> int:
        """Return number of days until expiry (negative if already expired)."""
        delta = self.not_after - datetime.datetime.now(datetime.timezone.utc)
        return delta.days
