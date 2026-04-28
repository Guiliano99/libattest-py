# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Example unit test cases for basic arithmetic."""

import unittest


class TestAdditionExample(unittest.TestCase):
    """Unit tests for simple addition behavior."""

    def test_addition_1_plus_2_equals_3(self) -> None:
        """
        GIVEN numbers 1 and 2.
        WHEN adding them,
        THEN is the result 3.
        """
        self.assertEqual(1 + 2, 3)


if __name__ == "__main__":
    unittest.main()
