# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Geographic Attestation Results claims-set (draft-richardson-rats-geographic-results-01).

A light, JSON-oriented pydantic v2 model of the draft's ``geographic-result-claims``
CDDL rule: a non-empty map of optional jurisdiction / data-center location claims that
a Verifier communicates to a Relying Party inside an EAR (typically as Verifier-authority
claims of one ``submods`` appraisal).

Scope, matching the posture of :mod:`libattest.ear`:

* **JSON-only.**  CBOR integer labels (0..13 in the draft) are *not* modelled — they are
  marked inconsistent/TBD in ``-01`` and await IANA allocation.  ``model_dump(by_alias=True)``
  emits the draft's exact kebab-case JSON key names.
* **Light validation.**  Field types, size/range bounds, and the one hard MUST ("at least
  one claim MUST be present") are enforced.  ISO 3166 registry checks and the cross-field
  nesting / exclave rules are left to the caller (see ``REFERENCES.md``).

References
----------
draft-richardson-rats-geographic-results-01: Geographic Attestation Results
  https://datatracker.ietf.org/doc/html/draft-richardson-rats-geographic-results-01

"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class GeographicResultClaims(BaseModel):
    """The draft's ``geographic-result-claims`` map — all fields optional, map non-empty.

    Python attributes are snake_case; each field's ``alias`` is the draft's exact JSON key
    (kebab-case, ``rack-U-number`` preserved verbatim).  ``populate_by_name=True`` lets you
    construct by either spelling; ``extra='allow'`` preserves unknown/future claims.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # --- Jurisdiction hierarchy: country -> subdivision -> city (+ exclave flags) ---
    jurisdiction_country: str | None = Field(
        default=None,
        alias="jurisdiction-country",
        description="Country of operation, ISO 3166-1 alpha-2 code. Optional.",
    )
    jurisdiction_country_exclave: bool | None = Field(
        default=None,
        alias="jurisdiction-country-exclave",
        description="True when the country location is an exclave. Optional.",
    )
    jurisdiction_subdivision: str | None = Field(
        default=None,
        alias="jurisdiction-subdivision",
        min_length=2,
        max_length=16,
        description="State/province, ISO 3166-2 subdivision code. Optional.",
    )
    jurisdiction_subdivision_exclave: bool | None = Field(
        default=None,
        alias="jurisdiction-subdivision-exclave",
        description="True when the subdivision location is an exclave. Optional.",
    )
    jurisdiction_city: str | None = Field(
        default=None,
        alias="jurisdiction-city",
        min_length=2,
        max_length=16,
        description="City name (subdivision-specific). Optional.",
    )
    jurisdiction_city_exclave: bool | None = Field(
        default=None,
        alias="jurisdiction-city-exclave",
        description="True when the city location is an exclave. Optional.",
    )
    enclosing_exclave_country: str | None = Field(
        default=None,
        alias="enclosing-exclave-country",
        description="Country enclosing an exclave, ISO 3166-1 alpha-2 code. Optional.",
    )

    # --- Relative / physical placement ---
    near_to: str | None = Field(
        default=None,
        alias="near-to",
        description="UUID (string form) of a known entity this location is near to. Optional.",
    )
    rack_u_number: int | None = Field(
        default=None,
        alias="rack-U-number",
        gt=0,
        description="Rack unit position, 1-based from the bottom (RU 1). Optional.",
    )
    cabinet_number: int | None = Field(
        default=None,
        alias="cabinet-number",
        gt=0,
        description="Data-center cabinet ordinal. Optional.",
    )
    hallway_number: int | None = Field(
        default=None,
        alias="hallway-number",
        ge=0,
        description="Hallway identifier. Optional.",
    )
    room_number: str | None = Field(
        default=None,
        alias="room-number",
        min_length=2,
        max_length=64,
        description="Room designation. Optional.",
    )
    floor_number: int | None = Field(
        default=None,
        alias="floor-number",
        description="Floor level (signed; may be negative for below-ground). Optional.",
    )
    data_center_name: str | None = Field(
        default=None,
        alias="data-center-name",
        min_length=2,
        max_length=64,
        description="Data-center facility identifier. Optional.",
    )

    @model_validator(mode="after")
    def _require_non_empty(self) -> GeographicResultClaims:
        """Enforce the draft's one hard MUST: at least one claim must be present.

        ``extra='allow'`` claims count too, so a set carrying only a future/unknown
        claim is still valid.
        """
        if not self.model_dump(by_alias=True, exclude_none=True):
            raise ValueError("geographic-result-claims must carry at least one claim")
        return self


def demo() -> None:
    """Assert-based self-check: round-trip, size bound, and the non-empty rule."""
    from pydantic import ValidationError

    # Round-trip: build -> dump by alias (exact draft keys) -> reparse -> equal.
    claims = GeographicResultClaims(
        jurisdiction_country="CH",
        jurisdiction_subdivision="ZH",
        jurisdiction_city="Zurich",
        rack_u_number=1,
        floor_number=-2,
        data_center_name="dc-alpha",
    )
    wire = claims.model_dump(by_alias=True, exclude_none=True)
    assert wire["jurisdiction-country"] == "CH"
    assert wire["rack-U-number"] == 1  # capital U preserved
    assert wire["floor-number"] == -2
    assert GeographicResultClaims.model_validate(wire) == claims

    # Non-empty rule: an all-None claims-set is rejected.
    try:
        GeographicResultClaims()
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("empty claims-set should have been rejected")

    # Size bound: subdivision > 16 chars is rejected.
    try:
        GeographicResultClaims(jurisdiction_subdivision="x" * 17)
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("oversized subdivision should have been rejected")

    # Range bound: rack unit must be > 0.
    try:
        GeographicResultClaims(rack_u_number=0)
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("rack-U-number 0 should have been rejected")

    print("geographic structures self-check OK")  # noqa: T201 - runnable self-check


if __name__ == "__main__":
    demo()
