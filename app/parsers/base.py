"""Shared parser errors and source IP validation."""

from ipaddress import ip_address


class ParseError(ValueError):
    """A recognized login record cannot be parsed reliably."""


def normalize_ip(value: str) -> str:
    try:
        return str(ip_address(value))
    except ValueError:
        # Do not echo arbitrary input, which may contain credentials.
        raise ParseError("invalid source IP") from None
