# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Add SPDX license identifier to all Python files that don't have it."""

import glob
import os.path

BASE_HEADER = """# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""

MD_HEADER = """<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->
"""


def add_header_to_file(path: str, header: str = BASE_HEADER):
    """Add SPDX header to a file at a given path, if the header doesn't already exist."""
    with open(path, encoding="utf-8") as f:
        content = f.read()

    # REUSE-IgnoreStart
    if "SPDX-License-Identifier:" not in content:
        # REUSE-IgnoreEnd
        with open(path, "w", encoding="utf-8") as f:
            if os.path.basename(path) in ["__init__", "__init__.py"]:
                f.write("# noqa D104 Missing docstring in public package" + "\n")
            f.write(header + "\n" + content)

        print(f"Header added to {path}")


# Use glob to find all .py files recursively
for dir_path in [
    "./src",
    "./scripts",
]:
    for file in glob.iglob(f"{dir_path}/**/*.py", recursive=True):
        add_header_to_file(file)

print("Python files done")

for dir_path in ["./"]:
    for file in glob.iglob(f"{dir_path}/**/*.md", recursive=True):
        add_header_to_file(file, MD_HEADER)

print("MD files done")
