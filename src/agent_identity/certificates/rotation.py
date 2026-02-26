"""Certificate rotation — automatic renewal before expiry.

CertRotator monitors a certificate's remaining validity and triggers
renewal when the certificate falls within the rotation window. Rotation
is thread-safe and can be called from scheduled background tasks.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from agent_identity.certificates.agent_cert import AgentCertificate
from agent_identity.certificates.ca import CertificateAuthority

logger = logging.getLogger(__name__)


@dataclass
class RotationResult:
    """Outcome of a rotation check.

    Parameters
    ----------
    rotated:
        True if a new certificate was issued.
    new_cert:
        The replacement certificate, or None if no rotation occurred.
    reason:
        Human-readable description of why rotation did or did not occur.
    """

    rotated: bool
    new_cert: AgentCertificate | None
    reason: str


class CertRotator:
    """Manages automatic certificate rotation for an agent.

    Rotation is triggered when the certificate has fewer days remaining
    than the configured *rotation_threshold_days*.

    Parameters
    ----------
    ca:
        The Certificate Authority used to issue replacement certificates.
    rotation_threshold_days:
        Rotate when this many days or fewer remain before expiry.
    default_validity_days:
        Validity period for newly issued replacement certificates.
    """

    def __init__(
        self,
        ca: CertificateAuthority,
        rotation_threshold_days: int = 30,
        default_validity_days: int = 365,
    ) -> None:
        self._ca = ca
        self._rotation_threshold_days = rotation_threshold_days
        self._default_validity_days = default_validity_days
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_and_rotate(self, cert: AgentCertificate) -> RotationResult:
        """Evaluate the certificate and rotate if within the threshold window.

        Parameters
        ----------
        cert:
            The certificate to evaluate.

        Returns
        -------
        RotationResult
            Indicates whether rotation occurred and the new certificate if so.
        """
        with self._lock:
            days_remaining = cert.days_remaining()

            if days_remaining > self._rotation_threshold_days:
                return RotationResult(
                    rotated=False,
                    new_cert=None,
                    reason=(
                        f"Certificate valid for {days_remaining} more days "
                        f"(threshold: {self._rotation_threshold_days})"
                    ),
                )

            if cert.is_expired():
                reason_prefix = "Certificate has expired"
            else:
                reason_prefix = (
                    f"Certificate expires in {days_remaining} day(s) "
                    f"(<= threshold {self._rotation_threshold_days})"
                )

            logger.info(
                "Rotating certificate for agent %r: %s",
                cert.agent_id,
                reason_prefix,
            )

            new_cert = self._ca.sign_agent_cert(
                agent_id=cert.agent_id,
                organization=cert.organization,
                capabilities=cert.capabilities,
                trust_level=cert.trust_level,
                validity_days=self._default_validity_days,
            )

            logger.info(
                "Issued replacement certificate for agent %r, serial=%s",
                cert.agent_id,
                new_cert.serial_number,
            )

            return RotationResult(
                rotated=True,
                new_cert=new_cert,
                reason=reason_prefix,
            )

    def force_rotate(self, cert: AgentCertificate) -> AgentCertificate:
        """Unconditionally issue a new certificate for the agent.

        Parameters
        ----------
        cert:
            The current certificate whose metadata will be carried forward.

        Returns
        -------
        AgentCertificate
            The newly issued certificate.
        """
        with self._lock:
            new_cert = self._ca.sign_agent_cert(
                agent_id=cert.agent_id,
                organization=cert.organization,
                capabilities=cert.capabilities,
                trust_level=cert.trust_level,
                validity_days=self._default_validity_days,
            )
            logger.info(
                "Force-rotated certificate for agent %r, serial=%s",
                cert.agent_id,
                new_cert.serial_number,
            )
            return new_cert
