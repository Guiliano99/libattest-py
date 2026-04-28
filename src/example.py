# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Example functions for the project template."""


def add_numbers(first: float, second: float) -> float:
    """Return the sum of two numbers.

    :param first: The first numeric value.
    :param second: The second numeric value.
    :return: The arithmetic sum of both values.
    """
    return first + second


def format_welcome(name: str, excited: bool = False) -> str:
    """Build a welcome message for a given name.

    :param name: The person to greet.
    :param excited: Whether to add emphatic punctuation.
    :return: The formatted greeting message.
    """
    suffix = "!" if excited else "."
    return f"Welcome, {name}{suffix}"
