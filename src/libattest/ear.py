# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAR (EAT Attestation Result) JWT helpers and token model.

Two layers live here:

* string helpers that inspect/verify an already-serialised EAR JWT
  (:func:`parse_ear_verdict`, :func:`verify_ear_jwt`, :func:`ear_is_affirming`); and
* a pydantic v2 model of the draft-ietf-rats-ear-04 claims-set (:class:`EARToken`
  and its subclasses) for building/parsing EARs as typed objects.

The model is a light proof-of-concept: it models the wire shapes and claim
aliases but enforces no normative MUSTs (appraisal logic stays the caller's job).

References
----------
draft-ietf-rats-ear-04: EAT Attestation Result
  https://datatracker.ietf.org/doc/draft-ietf-rats-ear/
draft-ietf-rats-ar4si: Attestation Results for Secure Interactions (tiers, verifier-id)
  https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/

"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    GetJsonSchemaHandler,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema

logger = logging.getLogger(__name__)

_AFFIRMING = "affirming"

#: EAT profile URI for this EAR draft revision (draft-ietf-rats-ear-04 §3).
#: Producers default to it; the verification boundary enforces it.
EAR_PROFILE = "tag:ietf.org,2026:rats/ear#04"


def parse_ear_verdict(ear_jwt: str) -> dict[str, str]:
    """Return ``{submod_name: ear.status}`` for every submodule in the EAR JWT.

    The JWT signature is **not** verified — use this only for verdict
    inspection inside a trusted verification pipeline, never for
    authentication.

    Parameters
    ----------
    ear_jwt:
        Compact-serialized JWT carrying an EAR payload.

    Returns
    -------
    dict[str, str]
        Mapping from submodule name to its ``ear.status`` value.  Submodules
        that do not carry an ``ear.status`` field receive the value
        ``"unknown"``.

    Raises
    ------
    ValueError
        If *ear_jwt* is not a well-formed JWT or its payload cannot be
        base64-decoded or JSON-parsed.

    """
    parts = ear_jwt.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT: fewer than two '.' delimiters")
    pad = (4 - len(parts[1]) % 4) % 4
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * pad))
    except Exception as exc:
        raise ValueError(f"Failed to decode EAR JWT payload: {exc}") from exc
    return {name: str(submod.get("ear.status", "unknown")) for name, submod in payload.get("submods", {}).items()}


def verify_ear_jwt(ear_jwt: str, public_key: "ec.EllipticCurvePublicKey") -> bool:
    """Verify the ES256 signature on *ear_jwt* using *public_key*.

    JWT ES256 carries the raw R||S signature (64 bytes for P-256), not DER.
    This function converts to DER before calling the ``cryptography`` verifier.

    Parameters
    ----------
    ear_jwt:
        Compact-serialized JWT (header.payload.signature).
    public_key:
        P-256 public key whose corresponding private key signed the JWT.

    Returns
    -------
    bool
        ``True`` when the signature is valid, ``False`` on any error.

    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        parts = ear_jwt.split(".")
        if len(parts) != 3:
            logger.warning("verify_ear_jwt: not a compact JWT (expected 3 parts)")
            return False

        message = (parts[0] + "." + parts[1]).encode("ascii")
        pad = (4 - len(parts[2]) % 4) % 4
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "=" * pad)

        # ES256 uses raw R||S (32 bytes each for P-256), not DER.
        if len(sig_bytes) != 64:
            logger.warning("verify_ear_jwt: unexpected ES256 signature length %d", len(sig_bytes))
            return False

        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        logger.warning("verify_ear_jwt: signature verification FAILED")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("verify_ear_jwt: unexpected error: %s", exc)
        return False


def ear_is_affirming(ear_jwt: str) -> bool:
    """Return ``True`` iff every submodule carries ``ear.status == 'affirming'``.

    Returns ``False`` (never raises) on parse errors, logging a warning instead.
    An EAR with zero submodules also returns ``False``.
    """
    try:
        verdicts = parse_ear_verdict(ear_jwt)
    except ValueError as exc:
        logger.warning("Failed to parse EAR JWT verdict: %s", exc)
        return False
    if not verdicts:
        logger.warning("EAR JWT contains no submodules")
        return False
    for name, verdict in verdicts.items():
        if verdict != _AFFIRMING:
            logger.warning("EAR submod %r: ear.status=%r", name, verdict)
            return False
    return True


# ── EAT byte-claim base type (JWT base64url <-> CWT raw bytes) ────────────────────
class Base64UrlBytes:
    """Immutable byte value with JWT (base64url) and CWT (raw bytes) encodings.

    Subclasses set ``_MIN_BYTES`` / ``_MAX_BYTES`` to declare size limits; ``None``
    means unbounded on that side.  The size check runs once in ``__init__``, so every
    construction path is validated.  Usable directly as a pydantic v2 field type:
    accepts raw bytes or a base64url string and serialises to a base64url string.
    """

    #: Inclusive lower bound on the byte length, or ``None`` for unbounded.
    _MIN_BYTES: int | None = None
    #: Inclusive upper bound on the byte length, or ``None`` for unbounded.
    _MAX_BYTES: int | None = None

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        """Store *raw* bytes after enforcing the subclass size bounds."""
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"{type(self).__name__} requires bytes, got {type(raw).__name__}")
        raw = bytes(raw)
        low, high = self._MIN_BYTES, self._MAX_BYTES
        if low is not None and len(raw) < low:
            raise ValueError(f"{type(self).__name__} must be ≥ {low} bytes, got {len(raw)}")
        if high is not None and len(raw) > high:
            raise ValueError(f"{type(self).__name__} must be ≤ {high} bytes, got {len(raw)}")
        self._raw = raw

    @classmethod
    def from_bytes(cls, value: bytes) -> Base64UrlBytes:
        """Construct from raw bytes (CWT / native representation)."""
        return cls(value)

    @classmethod
    def from_b64_str(cls, value: str) -> Base64UrlBytes:
        """Construct from a base64url string (JWT representation).

        Accepts input with or without ``=`` padding.  Decoding is strict: any character
        outside the base64url alphabet causes rejection rather than being silently dropped.

        :raises ValueError: If *value* is not valid base64url or the decoded bytes violate
            the subclass size bounds.
        """
        translated = value.translate(str.maketrans("-_", "+/"))
        padded = translated + "=" * (-len(translated) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid base64url string for {cls.__name__}: {value!r}") from exc
        return cls(raw)

    def to_bytes(self) -> bytes:
        """Return the raw bytes (CWT / native representation)."""
        return self._raw

    def as_b64_str(self) -> str:
        """Return the base64url string (JWT representation), without padding."""
        return base64.urlsafe_b64encode(self._raw).rstrip(b"=").decode("ascii")

    def __repr__(self) -> str:
        """Return ``ClassName('<base64url>')``."""
        return f"{type(self).__name__}({self.as_b64_str()!r})"

    def __eq__(self, other: object) -> bool:
        """Compare by exact type and raw bytes."""
        if isinstance(other, Base64UrlBytes):
            return type(self) is type(other) and self._raw == other._raw
        return NotImplemented

    def __hash__(self) -> int:
        """Hash by type and raw bytes (value semantics)."""
        return hash((type(self), self._raw))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Validate from bytes or base64url str; serialise to a base64url str."""
        from_str = core_schema.no_info_after_validator_function(
            cls.from_b64_str, core_schema.str_schema()
        )
        return core_schema.json_or_python_schema(
            json_schema=from_str,
            python_schema=core_schema.no_info_plain_validator_function(cls._pydantic_validate),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.as_b64_str(),
                return_schema=core_schema.str_schema(),
                when_used="json",
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema_obj: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        """Describe the JWT wire form (a base64url string) in JSON Schema."""
        schema = handler(core_schema.str_schema())
        schema.update(format="base64url", description=f"{cls.__name__}: base64url bytes (no padding).")
        return schema

    @classmethod
    def _pydantic_validate(cls, value: Any) -> Base64UrlBytes:
        """Coerce an instance, raw bytes, or base64url str into this type."""
        if isinstance(value, cls):
            return value
        if isinstance(value, (bytes, bytearray)):
            return cls.from_bytes(bytes(value))
        if isinstance(value, str):
            return cls.from_b64_str(value)
        raise ValueError(
            f"Cannot construct {cls.__name__} from {type(value).__name__}; "
            "expected bytes or a base64url str"
        )


class EATNonce(Base64UrlBytes):
    """EAT nonce (RFC 9711 §4.1): 8-64 bytes; base64url string when serialised as JWT."""

    _MIN_BYTES = 8
    _MAX_BYTES = 64


# ── EAR claims-set model (draft-ietf-rats-ear-04) ────────────────────────────────
class TrustworthinessTier(str, Enum):
    """AR4SI trustworthiness tier (draft-ietf-rats-ar4si §3.2), JSON spelling.

    CWT/CBOR integer code points (0/2/32/96) are out of scope for this JWT-only model.
    """

    NONE = "none"
    AFFIRMING = "affirming"
    WARNING = "warning"
    CONTRAINDICATED = "contraindicated"


class EARAppraisal(BaseModel):
    """One per-attester EAR-appraisal — a ``submods`` value (draft-04 §3.1, Figure 2).

    Light model: shapes and claim aliases only, no normative-MUST validation.  Unknown
    claims (``$$ear-appraisal-extension``) are preserved via ``extra='allow'``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    status: TrustworthinessTier = Field(
        alias="ear_status",
        description="Overall AR4SI tier for this attester (AR4SI §3.2). Mandatory.",
    )
    profile: str | None = Field(
        default=None,
        alias="eat_profile",
        description="EAT profile of this appraisal, if it carries extensions (RFC 9711 §6). Optional.",
    )
    trustworthiness_vector: dict[str, int] | None = Field(
        default=None,
        alias="ear_trustworthiness_vector",
        description="AR4SI vector: category -> claim code point (AR4SI §3.1). Optional.",
    )
    appraisal_policy_ids: list[str] | None = Field(
        default=None,
        alias="ear_appraisal_policy_ids",
        description="Ordered appraisal-policy identifiers; MUST NOT be empty. Optional.",
    )
    nonce: EATNonce | None = Field(
        default=None,
        alias="eat_nonce",
        description="Evidence freshness nonce for this appraisal, 8-64 bytes (RFC 9711 §4.1). Optional.",
    )
    attester_claims: dict[str, Any] | None = Field(
        default=None,
        alias="ear_attester_claims",
        description="Claims with Attester authority (extracted from Evidence). Optional.",
    )
    verifier_claims: dict[str, Any] | None = Field(
        default=None,
        alias="ear_verifier_claims",
        description="Claims with Verifier authority (added during appraisal). Optional.",
    )


class EARToken(BaseModel):
    """Top-level EAT Attestation Result token (draft-ietf-rats-ear-04 §3, Figure 1).

    Each field maps to its on-the-wire claim name via an alias where they differ, so
    ``model_dump(by_alias=True)`` yields the exact JWT claim keys.  Unknown top-level
    claims (``$$ear-extension``) are preserved via ``extra='allow'``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # --- Mandatory claims ---
    eat_profile: str = Field(
        default=EAR_PROFILE,
        description="EAT profile URI; MUST be the draft-04 tag (RFC 9711 §6). Mandatory.",
    )
    iat: int = Field(
        description="Issued-At, integer Unix seconds, no float (RFC 7519 §4.1.6). Mandatory.",
    )
    verifier_id: dict[str, str] = Field(
        alias="ear_verifier_id",
        description="Appraising Verifier identity {developer, build} (AR4SI §3.3). Mandatory.",
    )
    submods: dict[str, EARAppraisal] = Field(
        description="Map of label -> EAR-appraisal, >=1 entry (RFC 9711 §4.2.18). Mandatory.",
    )

    # --- Optional claims ---
    ear_status: TrustworthinessTier | None = Field(
        default=None,
        description="Overall AR4SI tier; <= worst submod (AR4SI §3.2). Optional.",
    )
    exp: int | None = Field(
        default=None,
        description="Expiration, integer Unix seconds, no float (RFC 7519 §4.1.4). Optional.",
    )
    raw_evidence: list[Any] | None = Field(
        default=None,
        alias="ear_raw_evidence",
        description="Unabridged evidence as a CMW record [media-type, value] (msg-wrap §3.1). Optional.",
    )
    nonce: EATNonce | None = Field(
        default=None,
        alias="eat_nonce",
        description="Freshness nonce echoed by the Verifier, 8-64 bytes (RFC 9711 §4.1). Optional.",
    )
    device_topology: dict[str, list[str]] | None = Field(
        default=None,
        alias="ear_device_topology",
        description="Attester graph as adjacency lists keyed by submods label. Optional.",
    )
