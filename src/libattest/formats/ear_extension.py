# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Format-owned OIDs for EAR certificate extensions."""

# Legacy deployment OID whose extension value is the raw EAR JWT. Deployments
# can override it through ``EAR_OID``; external code resolves the default by its
# registered name instead of importing this constant directly.
DEMO_EAR_EXTENSION_OID = "1.7.6.5.123"

__all__ = ["DEMO_EAR_EXTENSION_OID"]
