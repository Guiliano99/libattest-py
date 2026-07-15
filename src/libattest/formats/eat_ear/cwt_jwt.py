# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAT/EAR token models and CWT Claim Set <-> JWT-style View conversion.

Consolidated home (see docs/plans/eat_ear-consolidation.hardened.md) merging the
former ``libattest.ear`` (draft-ietf-rats-ear-04 EAR token model + JWT verdict
helpers) and ``libattest.formats.cwt_jwt`` (strict CWT Claim Set <-> JWT-style
View conversion).

No COSE signature is verified by the conversion helpers (:func:`cose_cwt_to_jwt_view`
renders unverified); the EAR JWT signature verifier (:func:`verify_ear_jwt`) is the
only authenticating entry point in this module.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from typing import Any, Optional, Union

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cwt import COSEMessage
from cwt.const import CWT_CLAIM_NAMES
from cwt.enums import COSEAlgs, COSEHeaders, COSETypes
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
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> CoreSchema:
        """Validate from bytes or base64url str; serialise to a base64url str."""
        from_str = core_schema.no_info_after_validator_function(cls.from_b64_str, core_schema.str_schema())
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
            f"Cannot construct {cls.__name__} from {type(value).__name__}; expected bytes or a base64url str"
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


# ============================================================================
#  CWT Claim Set <-> JWT-style View conversion (former libattest.formats.cwt_jwt)
# ============================================================================

ClaimLabel = int | str
ClaimSet = dict[ClaimLabel, object]
JwtStyleView = dict[str, object]


@dataclass(frozen=True)
class ClaimDef:
    """Definition of one CWT/EAT claim — the single source of truth for the maps below.

    label    : CBOR integer key used in CWT encoding.
    name     : JSON claim name used in JWT encoding.
    is_bytes : True if the JSON value is base64url text of a CBOR byte string
               (RFC 9711 §7.2.2), so it is base64url-decoded back to bytes.
    note     : human-readable description.
    refs     : normative reference(s) that define the claim.
    """

    label: int
    name: str
    is_bytes: bool = False
    note: str = ""
    refs: list[str] = field(default_factory=list)


# RFC 8392 §4 (standard CWT claims 1-8) + RFC 9711 (EAT claims). python-cwt is NOT used as
# the authority here because its 3.2.0 ships the older *draft* EAT labels (ueid=11, not 256).
CLAIMS: list[ClaimDef] = [
    ClaimDef(1, "iss", note="Issuer (StringOrURI)", refs=["RFC 8392 §3.1.1"]),
    ClaimDef(2, "sub", note="Subject (StringOrURI)", refs=["RFC 8392 §3.1.2"]),
    ClaimDef(3, "aud", note="Audience (StringOrURI)", refs=["RFC 8392 §3.1.3"]),
    ClaimDef(4, "exp", note="Expiration Time (NumericDate)", refs=["RFC 8392 §3.1.4"]),
    ClaimDef(5, "nbf", note="Not Before (NumericDate)", refs=["RFC 8392 §3.1.5"]),
    ClaimDef(6, "iat", note="Issued At / Timestamp", refs=["RFC 8392 §3.1.6", "RFC 9711 §4.3.1"]),
    ClaimDef(7, "jti", is_bytes=True, note="Token ID (CWT 'cti' byte string)", refs=["RFC 8392 §3.1.7"]),
    ClaimDef(8, "cnf", note="Confirmation / proof-of-possession key", refs=["RFC 8747 §3.1"]),
    ClaimDef(10, "eat_nonce", is_bytes=True, note="Freshness nonce (bstr or array)", refs=["RFC 9711 §4.1"]),
    ClaimDef(256, "ueid", is_bytes=True, note="Universal Entity ID", refs=["RFC 9711 §4.2.1"]),
    ClaimDef(257, "sueids", note="Semi-permanent UEIDs (name -> UEID)", refs=["RFC 9711 §4.2.2"]),
    ClaimDef(258, "oemid", is_bytes=True, note="Hardware OEM ID (PEN int or base64url)", refs=["RFC 9711 §4.2.3"]),
    ClaimDef(259, "hwmodel", is_bytes=True, note="Hardware model", refs=["RFC 9711 §4.2.4"]),
    ClaimDef(260, "hwversion", note="Hardware version [version, scheme]", refs=["RFC 9711 §4.2.5"]),
    ClaimDef(261, "uptime", note="Seconds since last boot", refs=["RFC 9711 §4.2.11"]),
    ClaimDef(262, "oemboot", note="OEM-authorised boot chain used", refs=["RFC 9711 §4.2.8"]),
    ClaimDef(263, "dbgstat", note="Debug status enumeration", refs=["RFC 9711 §4.2.9"]),
    ClaimDef(264, "location", note="Geographic location (WGS-84)", refs=["RFC 9711 §4.2.10"]),
    ClaimDef(265, "eat_profile", note="EAT profile URI/OID", refs=["RFC 9711 §4.3.2"]),
    ClaimDef(266, "submods", note="Submodules (name -> Claims-Set/token)", refs=["RFC 9711 §4.2.18"]),
    ClaimDef(267, "bootcount", note="Number of device boots", refs=["RFC 9711 §4.2.12"]),
    ClaimDef(268, "bootseed", is_bytes=True, note="Per-boot random seed", refs=["RFC 9711 §4.2.13"]),
    ClaimDef(269, "dloas", note="Digital Letters of Approval", refs=["RFC 9711 §4.2.14"]),
    ClaimDef(270, "swname", note="Software / firmware name", refs=["RFC 9711 §4.2.6"]),
    ClaimDef(271, "swversion", note="Software version", refs=["RFC 9711 §4.2.7"]),
    ClaimDef(272, "manifests", note="Software manifests (CoSWID/SWID)", refs=["RFC 9711 §4.2.15"]),
    ClaimDef(273, "measurements", note="Measurements", refs=["RFC 9711 §4.2.16"]),
    ClaimDef(274, "measres", note="Software measurement results", refs=["RFC 9711 §4.2.17"]),
    ClaimDef(275, "intuse", note="Intended use enumeration", refs=["RFC 9711 §4.3.3"]),
]

# Everything below is DERIVED from CLAIMS — one source of truth for label<->name<->byteness.
# python-cwt's CWT_CLAIM_NAMES is only a fallback base for any label the registry omits; the
# registry wins on conflicts (python-cwt 3.2.0 still ships the older *draft* EAT labels).
_CLAIM_NAME_BY_LABEL: dict[int, str] = {label: name for name, label in CWT_CLAIM_NAMES.items()}
_CLAIM_NAME_BY_LABEL.update({c.label: c.name for c in CLAIMS})
_CLAIM_LABEL_BY_NAME: dict[str, int] = {name: label for label, name in _CLAIM_NAME_BY_LABEL.items()}
_BYTE_CLAIM_NAMES = frozenset({c.name for c in CLAIMS if c.is_bytes} | {"boot_seed"})
# contracts-02: accept the pre-consolidation JSON key `boot_seed` as an input alias for the
# canonical RFC 9711 name `bootseed` (label 268) for one release; output always uses `bootseed`.
_CLAIM_LABEL_BY_NAME["boot_seed"] = _CLAIM_LABEL_BY_NAME["bootseed"]

_ALG = {a.value: a.name for a in COSEAlgs}
_HEADER_NAME_BY_LABEL = {
    COSEHeaders.ALG.value: "alg",
    COSEHeaders.KID.value: "kid",
    COSEHeaders.IV.value: "iv",
    COSEHeaders.CTY.value: "cty",
    COSEHeaders.CRIT.value: "crit",
}


def jwt_claims_to_cwt_claim_set(claims: Mapping[str, object]) -> ClaimSet:
    """Map JSON/JWT claim names to a CBOR CWT Claim Set.

    Arguments:
        claims: JSON-compatible JWT claims. Recognized byte-valued claims must
            use base64url text; ``jti`` is encoded as UTF-8 when supplied as a
            normal JWT string.

    Returns:
        A CWT Claim Set using registered integer labels and CBOR byte strings
        for recognized byte-valued claims.

    Raises:
        ValueError: If a recognized base64url claim is malformed.

    """
    return _claims_to_cwt_claim_set(claims, jti_is_jwt_text=True)


def jwt_style_view_to_cwt_claim_set(view: Mapping[str, object]) -> ClaimSet:
    """Map a CWT JSON view produced by this module back to a CWT Claim Set.

    Arguments:
        view: A readable JWT-style view. A top-level ``payload`` object is
            unwrapped when present; metadata keys and ``*_utc`` display fields
            are excluded.

    Returns:
        A CWT Claim Set with recognized byte-valued claims restored.

    Raises:
        ValueError: If ``payload`` is present but is not an object, or if a
            recognized base64url claim is malformed.

    """
    payload = view.get("payload")
    if payload is None:
        return _claims_to_cwt_claim_set(view, jti_is_jwt_text=False)
    if not isinstance(payload, Mapping):
        raise ValueError("JWT-style view payload must be an object")
    if not all(isinstance(key, str) for key in payload):
        raise ValueError("JWT-style view payload keys must be strings")
    return _claims_to_cwt_claim_set(payload, jti_is_jwt_text=False)


def cwt_claim_set_to_jwt_view(claims: Mapping[ClaimLabel, object]) -> JwtStyleView:
    """Render a CWT Claim Set as a readable JWT-style JSON view.

    Arguments:
        claims: CWT Claim Set values keyed by CWT/EAT labels or private names.

    Returns:
        A JSON-compatible mapping. Every CBOR byte string is emitted as
        unpadded base64url text, as required by RFC 9711 JSON serialization.

    """
    rendered = _to_jwt_json(dict(claims))
    if not isinstance(rendered, dict):
        raise AssertionError("CWT Claim Set rendering must produce a JSON object")
    return {str(key): value for key, value in rendered.items()}


def cose_cwt_to_jwt_view(token: bytes) -> JwtStyleView:
    """Render an unverified COSE-wrapped CWT as a JWT-style JSON view.

    Arguments:
        token: Exactly one CBOR item containing a COSE CWT, optionally wrapped
            in the CWT tag (61).

    Returns:
        A mapping with COSE metadata, readable headers, and a rendered CWT
        payload. An encrypted message with no readable payload contains an
        explicit unreadable-payload marker.

    Raises:
        ValueError: If token framing is invalid, has trailing data, or has a
            readable payload that is not a CBOR map.

    Notes:
        This function does not verify a COSE signature and must not be used to
        establish token trust.

    """
    outer = _decode_single_cbor_item(token, "CWT")
    encoded_message = token
    if isinstance(outer, cbor2.CBORTag) and outer.tag == 61:
        encoded_message = cbor2.dumps(outer.value)
    message = COSEMessage.loads(encoded_message)
    header = _render_cose_headers(message.protected, message.unprotected)
    view: JwtStyleView = {"_meta": {"cose_type": str(message.type)}, "header": header}

    if message.type in (COSETypes.ENCRYPT0.value, COSETypes.ENCRYPT.value) or not message.payload:
        view["payload"] = "<no readable payload (encrypted?)>"
        return view

    payload = _decode_single_cbor_item(bytes(message.payload), "COSE CWT payload")
    if not isinstance(payload, Mapping):
        raise ValueError("COSE CWT payload must decode to a CBOR map")
    view["payload"] = cwt_claim_set_to_jwt_view(payload)
    return view


def _claims_to_cwt_claim_set(claims: Mapping[str, object], *, jti_is_jwt_text: bool) -> ClaimSet:
    """Convert a JSON object to its CWT Claim Set representation."""
    if "boot_seed" in claims and "bootseed" in claims:
        raise ValueError("boot_seed and bootseed are mutually exclusive aliases for label 268")
    result: ClaimSet = {}
    for name, value in claims.items():
        if name.startswith("_") or name.endswith("_utc"):
            continue
        label: ClaimLabel = _CLAIM_LABEL_BY_NAME.get(name, _parse_private_claim_label(name))
        result[label] = _to_cwt_value(name, value, jti_is_jwt_text=jti_is_jwt_text)
    return result


def _to_cwt_value(name: str, value: object, *, jti_is_jwt_text: bool) -> object:
    """Restore a recognized CWT byte-valued claim from its JSON representation.

    A byte-claim value is base64url-decoded only when it is text. A non-str value
    passes through unchanged so RFC 9711's alternative forms survive: an integer
    ``oemid`` PEN (§4.2.3) and an ``eat_nonce`` *array* of base64url nonces (§4.1),
    whose elements are decoded individually.
    """
    if name == "jti" and jti_is_jwt_text and isinstance(value, str):
        return value.encode("utf-8")
    if name in _BYTE_CLAIM_NAMES:
        if isinstance(value, list):
            return [_decode_base64url(item, name) if isinstance(item, str) else item for item in value]
        if isinstance(value, str):
            return _decode_base64url(value, name)
        if isinstance(value, (bytes, bytearray)):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return value  # integer oemid PEN (RFC 9711 §4.2.3); bool is not a valid PEN
        raise ValueError(f"{name} must be base64url text, raw bytes, an int PEN, or an array of those")
    return value


def _decode_base64url(value: object, claim_name: str) -> bytes:
    """Decode an unpadded or padded base64url string with strict validation."""
    if not isinstance(value, str):
        raise ValueError(f"{claim_name} must be base64url text")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError(f"{claim_name} is not valid base64url text") from exc


def _parse_private_claim_label(name: str) -> ClaimLabel:
    """Use integer labels encoded as JSON object keys, otherwise preserve a private name."""
    return int(name) if name.lstrip("-").isdigit() else name


def _to_jwt_json(value: object) -> object:
    """Recursively make a CBOR value JSON-compatible."""
    if isinstance(value, (bytes, bytearray)):
        return _base64url(bytes(value))
    if isinstance(value, (list, tuple)):
        return [_to_jwt_json(item) for item in value]
    if isinstance(value, Mapping):
        return {_render_claim_key(key): _to_jwt_json(item) for key, item in value.items()}
    return value


def _render_claim_key(key: object) -> str:
    """Render registered labels as names and all other map keys as JSON keys."""
    if isinstance(key, int):
        return _CLAIM_NAME_BY_LABEL.get(key, str(key))
    return str(key)


def _base64url(value: bytes) -> str:
    """Return unpadded base64url text."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_single_cbor_item(data: bytes, context: str) -> object:
    """Decode exactly one CBOR item and reject any trailing bytes."""
    decoder = BytesIO(data)
    try:
        value = cbor2.load(decoder)
    except cbor2.CBORDecodeError as exc:
        raise ValueError(f"{context} is not valid CBOR") from exc
    if decoder.read(1):
        raise ValueError(f"{context} contains trailing bytes")
    return value


def _render_cose_headers(
    protected: Mapping[str | int, Any] | None,
    unprotected: Mapping[str | int, Any] | None,
) -> JwtStyleView:
    """Render COSE header parameters without assuming a signature was verified."""
    header: JwtStyleView = {}
    for label, value in {**(protected or {}), **(unprotected or {})}.items():
        rendered_label: int | str = label
        name = (
            _HEADER_NAME_BY_LABEL.get(rendered_label, str(rendered_label))
            if isinstance(rendered_label, int)
            else rendered_label
        )
        if rendered_label == COSEHeaders.ALG.value and isinstance(value, int):
            header[name] = _ALG.get(value, value)
        elif isinstance(value, (bytes, bytearray)):
            header[name] = _readable_header_value(bytes(value))
        else:
            header[name] = value
    return header


def _readable_header_value(value: bytes) -> str:
    """Prefer printable ASCII header values, otherwise return base64url text."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return _base64url(value)
    return text if text.isprintable() else _base64url(value)


# ============================================================================
#  EAT Evidence claims-set models (RFC 9711 §4) — the typed Evidence payload
# ============================================================================


def _drop_empty(obj: Any) -> Any:
    """Recursively drop dict entries whose value is an empty dict (e.g. an all-default submodel)."""
    if isinstance(obj, dict):
        return {k: _drop_empty(v) for k, v in obj.items() if v != {}}
    if isinstance(obj, list):
        return [_drop_empty(i) for i in obj]
    return obj


class _ClaimsModel(BaseModel):
    """Common base for the EAT Evidence claims-set models.

    ``populate_by_name`` allows construction by field name while serialising to each field's
    spec JSON alias; ``extra='allow'`` round-trips any unmodelled claim untouched.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    def to_json_dict(self) -> dict:
        """Clean JSON dict: alias names, None omitted, enums -> values, empty dicts dropped."""
        return _drop_empty(self.model_dump(mode="json", by_alias=True, exclude_none=True))

    def to_json(self, indent: int = 2) -> str:
        """Pretty JSON string of :meth:`to_json_dict`."""
        return json.dumps(self.to_json_dict(), indent=indent)


class DebugStatus(str, Enum):
    """dbgstat — Debug Status claim (RFC 9711 §4.2.9), least- to most-secure."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    DISABLED_SINCE_BOOT = "disabled-since-boot"
    DISABLED_PERMANENTLY = "disabled-permanently"
    DISABLED_FULLY_AND_PERMANENTLY = "disabled-fully-and-permanently"


class IntendedUse(str, Enum):
    """intuse — Intended Use claim (RFC 9711 §4.3.3)."""

    GENERIC = "generic"
    REGISTRATION = "registration"
    PROVISIONING = "provisioning"
    CERTIFICATE_ISSUANCE = "csi"
    PROOF_OF_POSSESSION = "pop"
    ATTESTATION = "attestation"


class Location(_ClaimsModel):
    """location — Geographic location claim (RFC 9711 §4.2.10), WGS-84.

    The EAT device-location Evidence claim; distinct from the verifier-side
    ``GeographicResultClaims`` (jurisdiction/data-centre), which stays where it is.
    """

    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    accuracy: Optional[float] = None
    altitude_accuracy: Optional[float] = None
    heading: Optional[float] = None
    speed: Optional[float] = None


class DLOAEntry(_ClaimsModel):
    """Single entry in the dloas claim (RFC 9711 §4.2.14)."""

    dloa_registrar: str = ""
    dloa_credential: str = ""


class SoftwareMeasurement(_ClaimsModel):
    """Single entry inside the measurements claim (RFC 9711 §4.2.16)."""

    mkey: Optional[str] = None
    hash_alg: Optional[str] = None
    value: Optional[str] = None


class MeasurementResult(_ClaimsModel):
    """Single entry in the measres claim (RFC 9711 §4.2.17)."""

    measurement_system: str = ""
    results: list[list[str]] = Field(default_factory=list)


class EATClaimsSet(_ClaimsModel):
    """EAT Claims-Set — the typed CWT/JWT payload carrying device Evidence (RFC 9711 §4).

    Distinct from the EAR result token (:class:`EARToken`): this models the *Evidence* a
    device produces (see CONTEXT.md's Evidence vs EAR distinction). All fields optional;
    unmodelled claims round-trip via ``extra='allow'``. Byte-valued claims use
    :class:`Base64UrlBytes` (JSON base64url <-> CWT raw bytes); ``eat_nonce`` uses the
    length-bounded :class:`EATNonce` and also accepts an array (RFC 9711 §4.1); ``oemid``
    accepts either an integer PEN or bytes (RFC 9711 §4.2.3).
    """

    # §4.1 Freshness
    eat_nonce: Optional[Union[EATNonce, list[EATNonce]]] = None
    # §4.2 Entity identity
    ueid: Optional[Base64UrlBytes] = None
    sueids: Optional[dict[str, str]] = None
    oemid: Optional[Union[int, Base64UrlBytes]] = None
    hwmodel: Optional[Base64UrlBytes] = None
    hwversion: Optional[list] = None
    uptime: Optional[int] = None
    oemboot: Optional[bool] = None
    dbgstat: Optional[Union[DebugStatus, str, int]] = None
    location: Optional[Location] = None
    eat_profile: Optional[str] = None
    bootcount: Optional[int] = None
    bootseed: Optional[Base64UrlBytes] = None
    dloas: Optional[list[DLOAEntry]] = None
    # Software identity / integrity
    swname: Optional[str] = None
    swversion: Optional[Union[str, list]] = None
    manifests: Optional[list] = None
    measurements: Optional[list[SoftwareMeasurement]] = None
    measres: Optional[list[MeasurementResult]] = None
    # §4.3 Other
    intuse: Optional[Union[IntendedUse, str]] = None
    # NOTE: `secboot` was dropped — it has no ClaimDef and would resolve via python-cwt's
    # *draft* fallback label, contradicting the "registry is the single source of truth"
    # invariant. Unmodelled secure-boot claims still round-trip via extra="allow".
    # Standard JWT / CWT claims
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[Union[str, list[str]]] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[Base64UrlBytes] = None
    # Submodules (nested Claims-Set, or ["JWT"/"CBOR", token])
    submods: Optional[dict[str, Union["EATClaimsSet", list]]] = None

    def to_cwt_claims(self, *, as_hex: bool = True) -> Union[str, bytes]:
        """Serialise to a CBOR CWT Claim Set (JSON names -> integer labels).

        Routes through :func:`jwt_style_view_to_cwt_claim_set` (``jti`` treated as a base64url
        byte-claim, NOT JWT text), so the produced ``cti`` (label 7) holds the decoded ``jti``
        bytes rather than their UTF-8 encoding.
        """
        claim_set = jwt_style_view_to_cwt_claim_set(self.to_json_dict())
        enc = cbor2.dumps(claim_set)
        return binascii.hexlify(enc).decode() if as_hex else enc

    # NOTE (hardening security-01): a ``from_cwt`` constructor was intentionally NOT carried
    # over. Decoding signed/MACed CWT bytes into a typed "trusted" object without verifying the
    # COSE signature would promote an unverified-Evidence path into the public API of an
    # attestation library. A verified decoder must take a required COSE verify key and check the
    # signature before decoding; that is a new design decision, deferred until a caller needs it.


# Resolve the forward reference in EATClaimsSet.submods.
EATClaimsSet.model_rebuild()


def demo() -> None:
    """Runnable self-check (hardening evidence). Run: ``python -m libattest.formats.eat_ear.cwt_jwt``.

    Asserts the three properties the plan's hardening called out: (a) the ALG de-collision did
    not break crypto, (b) ``jti`` round-trips to the correct ``cti`` bytes, and (c) the registry
    emits the canonical RFC name for label 268 while still accepting the old ``boot_seed`` alias.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    from libattest.formats.eat_ear import cwt_jwt_utils as _u

    # (a) ES256 sign/verify + JOSE-HPKE-0 seal/open still work after the merge/de-collision.
    priv = _ec.generate_private_key(_ec.SECP256R1())
    assert _u.verify_es256(_u.sign_es256({"iss": "demo"}, priv), priv.public_key())["iss"] == "demo"
    _hdr, plaintext = _u.open_integrated(_u.seal_integrated(b"ping", {}, priv.public_key()), priv)
    assert plaintext == b"ping"

    # (b) jti round-trips to the correct cti (label 7) bytes, not its UTF-8 encoding.
    raw_jti = bytes(range(8))
    claim_set = cbor2.loads(EATClaimsSet(jti=raw_jti, ueid=b"device-01").to_cwt_claims(as_hex=False))
    assert claim_set[7] == raw_jti, claim_set[7]
    assert claim_set[256] == b"device-01", claim_set[256]

    # (c) label 268 emits the canonical RFC name `bootseed`; the old `boot_seed` alias still maps in.
    assert _CLAIM_NAME_BY_LABEL[268] == "bootseed"
    assert jwt_claims_to_cwt_claim_set({"boot_seed": _base64url(b"seed")})[268] == b"seed"

    print("cwt_jwt demo OK: crypto round-trip, jti->cti, label-268 bootseed")  # noqa: T201


__all__ = [
    # EAR token model + JWT helpers (former libattest.ear)
    "EAR_PROFILE",
    "Base64UrlBytes",
    "EATNonce",
    "EARAppraisal",
    "EARToken",
    "TrustworthinessTier",
    "ear_is_affirming",
    "parse_ear_verdict",
    "verify_ear_jwt",
    # CWT Claim Set <-> JWT-style View conversion (former formats.cwt_jwt)
    "ClaimSet",
    "JwtStyleView",
    "cose_cwt_to_jwt_view",
    "cwt_claim_set_to_jwt_view",
    "jwt_claims_to_cwt_claim_set",
    "jwt_style_view_to_cwt_claim_set",
    # EAT Evidence claims-set registry + models
    "ClaimDef",
    "CLAIMS",
    "DebugStatus",
    "IntendedUse",
    "Location",
    "DLOAEntry",
    "SoftwareMeasurement",
    "MeasurementResult",
    "EATClaimsSet",
]


if __name__ == "__main__":
    demo()
