# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Put this prototype folder on ``sys.path`` so its flat modules import cleanly.

Lets ``pytest`` collect ``test_key_binding.py`` regardless of the working
directory, matching how ``python demo.py`` / ``python test_key_binding.py`` run.
"""

import os
import sys

# Append (not prepend): the flat module names here are unique, so this makes them
# importable without any risk of shadowing a real package during a full-repo run.
_here = os.path.dirname(__file__)
if _here not in sys.path:
    sys.path.append(_here)
